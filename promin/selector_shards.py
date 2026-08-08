"""Deterministic selector sharding with immutable per-process limits.

The module creates and checks data-only shard manifests.  ``run_selector_shard``
is intentionally separate from static admission: it is a bounded dynamic child
process route and returns ``UNAVAILABLE`` whenever the current host cannot
enforce both the declared timeout and memory limit.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import Any, Final


class SelectorShardError(ValueError):
    """Raised when a shard manifest cannot prove exact, safe coverage."""


MANIFEST_SCHEMA: Final = "promin.selector-shards.v1"
VALIDATION_SCHEMA: Final = "promin.selector-shard-validation.v1"
AGGREGATE_SCHEMA: Final = "promin.selector-shard-aggregate.v1"
RUNNER_RECEIPT_SCHEMA: Final = "promin.selector-shard-runner-receipt.v1"
_REQUIRED_MANIFEST_FIELDS: Final = frozenset(
    {
        "schema",
        "selector_set_id",
        "selectors",
        "selector_count",
        "marker_expression",
        "per_process",
        "aggregate",
        "shards",
    }
)
_OPTIONAL_MANIFEST_DIGEST_FIELDS: Final = frozenset({"selector_digest", "manifest_digest"})
_SHARD_FIELDS: Final = frozenset({"id", "selectors", "limits"})
_LIMIT_FIELDS: Final = frozenset({"timeout_seconds", "memory_bytes"})
_AGGREGATE_FIELDS: Final = frozenset({"timeout_seconds"})
_ROW_FIELDS: Final = frozenset({"id", "status", "elapsed_seconds"})
_TERMINAL_STATUSES: Final = frozenset(
    {"PASS", "FAIL", "TIMEOUT", "UNAVAILABLE", "INVALID_HARNESS"}
)
_SHARD_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_MARKER_TOKEN = re.compile(r"\s*(?:(and|or|not)|([A-Za-z_][A-Za-z0-9_]*)|([()]))")
_MAX_MANIFEST_BYTES: Final = 1 * 1024 * 1024
_REPARSE_POINT: Final = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _require_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SelectorShardError(f"{label} must be a mapping")
    if any(not isinstance(key, str) for key in value):
        raise SelectorShardError(f"{label} keys must be strings")
    return value


def _require_exact_fields(value: object, fields: frozenset[str], label: str) -> Mapping[str, object]:
    mapping = _require_mapping(value, label)
    actual = frozenset(mapping)
    if actual != fields:
        missing = sorted(fields - actual)
        unexpected = sorted(actual - fields)
        raise SelectorShardError(
            f"{label} fields must be exact; missing={missing}; unexpected={unexpected}"
        )
    return mapping


def _require_manifest_fields(value: object) -> Mapping[str, object]:
    mapping = _require_mapping(value, "selector shard manifest")
    actual = frozenset(mapping)
    allowed = _REQUIRED_MANIFEST_FIELDS | _OPTIONAL_MANIFEST_DIGEST_FIELDS
    if not _REQUIRED_MANIFEST_FIELDS.issubset(actual) or not actual.issubset(allowed):
        missing = sorted(_REQUIRED_MANIFEST_FIELDS - actual)
        unexpected = sorted(actual - allowed)
        raise SelectorShardError(
            f"selector shard manifest fields are invalid; missing={missing}; unexpected={unexpected}"
        )
    return mapping


def _require_positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SelectorShardError(f"{label} must be a positive integer")
    return value


def _require_nonnegative_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SelectorShardError(f"{label} must be a finite non-negative number")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < 0:
        raise SelectorShardError(f"{label} must be a finite non-negative number")
    return normalized


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise SelectorShardError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_selector(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise SelectorShardError(f"{label} must be a non-empty selector")
    if value.startswith("-") or value.startswith(("/", "\\")) or "\\" in value:
        raise SelectorShardError(f"{label} must be a safe relative selector")
    selector_path = value.split("::", 1)[0]
    if any(component in {"", ".", ".."} for component in selector_path.split("/")):
        raise SelectorShardError(f"{label} must be a safe relative selector")
    if "\r" in value or "\n" in value:
        raise SelectorShardError(f"{label} must be a single-line selector")
    return value


def _normalize_selectors(value: object, label: str = "selectors") -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise SelectorShardError(f"{label} must be a non-empty selector list")
    selectors = [_require_selector(item, f"{label}[{index}]") for index, item in enumerate(value)]
    if not selectors:
        raise SelectorShardError(f"{label} must be non-empty")
    if len(set(selectors)) != len(selectors):
        raise SelectorShardError(f"{label} contains duplicate selectors")
    # A reviewed manifest may group top-level selectors by domain.  Canonical
    # digesting therefore sorts the set here; exact membership, not presentation
    # order, is the invariant.  Individual shard lists remain sorted below.
    return sorted(selectors)


def _marker_tokens(expression: str) -> list[str]:
    position = 0
    tokens: list[str] = []
    while position < len(expression):
        match = _MARKER_TOKEN.match(expression, position)
        if match is None:
            raise SelectorShardError("marker_expression has invalid syntax")
        position = match.end()
        token = next(group for group in match.groups() if group is not None)
        tokens.append(token)
    if not tokens:
        raise SelectorShardError("marker_expression must be non-empty")
    return tokens


def _normalize_marker_expression(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise SelectorShardError("marker_expression must be a non-empty trimmed string")
    tokens = _marker_tokens(value)
    position = 0

    def parse_expression() -> None:
        nonlocal position
        parse_term()
        while position < len(tokens) and tokens[position] == "or":
            position += 1
            parse_term()

    def parse_term() -> None:
        nonlocal position
        parse_factor()
        while position < len(tokens) and tokens[position] == "and":
            position += 1
            parse_factor()

    def parse_factor() -> None:
        nonlocal position
        while position < len(tokens) and tokens[position] == "not":
            position += 1
        if position >= len(tokens):
            raise SelectorShardError("marker_expression has incomplete syntax")
        token = tokens[position]
        if token == "(":
            position += 1
            parse_expression()
            if position >= len(tokens) or tokens[position] != ")":
                raise SelectorShardError("marker_expression has unbalanced parentheses")
            position += 1
            return
        if token in {"and", "or", "not", ")"}:
            raise SelectorShardError("marker_expression has invalid syntax")
        position += 1

    parse_expression()
    if position != len(tokens):
        raise SelectorShardError("marker_expression has invalid syntax")
    return " ".join(tokens)


def _selector_digest(selectors: Sequence[str], marker_expression: str) -> str:
    return _sha256({"marker_expression": marker_expression, "selectors": list(selectors)})


def _manifest_digest(manifest: Mapping[str, object]) -> str:
    payload = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    return _sha256(payload)


def _normalize_limits(value: object, label: str) -> dict[str, int]:
    limits = _require_exact_fields(value, _LIMIT_FIELDS, label)
    return {
        "timeout_seconds": _require_positive_int(limits["timeout_seconds"], f"{label}.timeout_seconds"),
        "memory_bytes": _require_positive_int(limits["memory_bytes"], f"{label}.memory_bytes"),
    }


def _normalize_manifest(
    manifest: Mapping[str, object], *, expected_selectors: Sequence[str] | None = None
) -> dict[str, object]:
    candidate = _require_manifest_fields(manifest)
    if candidate["schema"] != MANIFEST_SCHEMA:
        raise SelectorShardError(f"manifest schema must be {MANIFEST_SCHEMA}")

    selectors = _normalize_selectors(candidate["selectors"])
    if (
        isinstance(candidate["selector_count"], bool)
        or not isinstance(candidate["selector_count"], int)
        or candidate["selector_count"] != len(selectors)
    ):
        raise SelectorShardError("selector_count does not match selectors")
    marker_expression = _normalize_marker_expression(candidate["marker_expression"])
    selector_set_id = candidate["selector_set_id"]
    if (
        not isinstance(selector_set_id, str)
        or not _SHARD_ID.fullmatch(selector_set_id)
        or selector_set_id != selector_set_id.strip()
    ):
        raise SelectorShardError("selector_set_id must be a safe lowercase identifier")
    expected_selector_digest = _selector_digest(selectors, marker_expression)
    if "selector_digest" in candidate and _require_digest(
        candidate["selector_digest"], "selector_digest"
    ) != expected_selector_digest:
        raise SelectorShardError("selector digest does not bind selectors and marker_expression")

    if expected_selectors is not None:
        normalized_expected = _normalize_selectors(expected_selectors, "expected_selectors")
        if selectors != normalized_expected:
            missing = sorted(set(normalized_expected) - set(selectors))
            unexpected = sorted(set(selectors) - set(normalized_expected))
            raise SelectorShardError(
                f"selector coverage is not exact; missing={missing}; unexpected={unexpected}"
            )

    per_process = _normalize_limits(candidate["per_process"], "per_process")
    aggregate = _require_exact_fields(candidate["aggregate"], _AGGREGATE_FIELDS, "aggregate")
    aggregate_timeout = _require_positive_int(aggregate["timeout_seconds"], "aggregate.timeout_seconds")
    raw_shards = candidate["shards"]
    if isinstance(raw_shards, (str, bytes)) or not isinstance(raw_shards, Sequence) or not raw_shards:
        raise SelectorShardError("shards must be a non-empty list")
    if len(raw_shards) > len(selectors):
        raise SelectorShardError("shards cannot outnumber selectors")

    shard_records: list[dict[str, object]] = []
    shard_ids: list[str] = []
    all_assigned: list[str] = []
    for index, raw_shard in enumerate(raw_shards, start=1):
        shard = _require_exact_fields(raw_shard, _SHARD_FIELDS, f"shards[{index - 1}]")
        shard_id = shard["id"]
        if not isinstance(shard_id, str) or not _SHARD_ID.fullmatch(shard_id):
            raise SelectorShardError(f"shards[{index - 1}].id must be a safe lowercase identifier")
        shard_ids.append(shard_id)
        raw_shard_selectors = shard["selectors"]
        if isinstance(raw_shard_selectors, (str, bytes)) or not isinstance(raw_shard_selectors, Sequence):
            raise SelectorShardError(f"shards[{index - 1}].selectors must be a list")
        shard_selectors = [
            _require_selector(item, f"shards[{index - 1}].selectors[{selector_index}]")
            for selector_index, item in enumerate(raw_shard_selectors)
        ]
        if not shard_selectors:
            raise SelectorShardError(f"shards[{index - 1}].selectors must be non-empty")
        all_assigned.extend(shard_selectors)
        shard_limits = _normalize_limits(shard["limits"], f"shards[{index - 1}].limits")
        if shard_limits != per_process:
            raise SelectorShardError("shard limits must exactly match immutable per_process limits")
        shard_records.append(
            {
                "id": shard_id,
                # Reviewers may order selectors by subsystem.  Canonicalize
                # only for digest/execution; coverage remains exact either way.
                "selectors": sorted(shard_selectors),
                "limits": shard_limits,
            }
        )

    if len(set(shard_ids)) != len(shard_ids):
        raise SelectorShardError("shards contain duplicate ids")
    duplicate_selectors = sorted(
        selector for selector in set(all_assigned) if all_assigned.count(selector) > 1
    )
    if duplicate_selectors:
        raise SelectorShardError(f"shards contain duplicate selectors: {duplicate_selectors}")
    missing = sorted(set(selectors) - set(all_assigned))
    unexpected = sorted(set(all_assigned) - set(selectors))
    if missing or unexpected:
        raise SelectorShardError(
            f"shard selector coverage is not exact; missing={missing}; unexpected={unexpected}"
        )

    normalized: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "selector_set_id": selector_set_id,
        "selector_digest": expected_selector_digest,
        "selectors": selectors,
        "selector_count": len(selectors),
        "marker_expression": marker_expression,
        "per_process": per_process,
        "aggregate": {"timeout_seconds": aggregate_timeout},
        "shards": shard_records,
    }
    computed_manifest_digest = _manifest_digest(normalized)
    if "manifest_digest" in candidate and _require_digest(
        candidate["manifest_digest"], "manifest_digest"
    ) != computed_manifest_digest:
        raise SelectorShardError("manifest digest does not bind the manifest contents")
    normalized["manifest_digest"] = computed_manifest_digest
    return normalized


def build_selector_shard_manifest(
    selectors: Sequence[str],
    *,
    shard_count: int,
    timeout_seconds: int,
    memory_bytes: int,
    aggregate_timeout_seconds: int,
    marker_expression: str = "not scale",
) -> dict[str, object]:
    """Build a deterministic manifest whose shard union equals its selectors."""

    normalized_selectors = _normalize_selectors(selectors)
    normalized_marker = _normalize_marker_expression(marker_expression)
    count = _require_positive_int(shard_count, "shard_count")
    if count > len(normalized_selectors):
        raise SelectorShardError("shard_count cannot exceed selector count")
    per_process = {
        "timeout_seconds": _require_positive_int(timeout_seconds, "timeout_seconds"),
        "memory_bytes": _require_positive_int(memory_bytes, "memory_bytes"),
    }
    aggregate = {"timeout_seconds": _require_positive_int(aggregate_timeout_seconds, "aggregate_timeout_seconds")}
    assignments: list[list[str]] = [[] for _ in range(count)]
    for index, selector in enumerate(normalized_selectors):
        assignments[index % count].append(selector)
    selector_digest = _selector_digest(normalized_selectors, normalized_marker)
    manifest: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "selector_set_id": f"selector-set-{selector_digest[:12]}",
        "selectors": normalized_selectors,
        "selector_count": len(normalized_selectors),
        "marker_expression": normalized_marker,
        "per_process": per_process,
        "aggregate": aggregate,
        "shards": [
            {
                "id": f"shard-{index + 1:03d}",
                "selectors": assignment,
                "limits": dict(per_process),
            }
            for index, assignment in enumerate(assignments)
        ],
    }
    return _normalize_manifest(manifest)


def validate_selector_shard_manifest(
    manifest: Mapping[str, object],
    *,
    expected_selectors: Sequence[str] | None = None,
) -> dict[str, object]:
    """Verify exact union coverage and invariant per-shard resource limits."""

    normalized = _normalize_manifest(manifest, expected_selectors=expected_selectors)
    expected = (
        _normalize_selectors(expected_selectors, "expected_selectors")
        if expected_selectors is not None
        else list(normalized["selectors"])
    )
    selectors = list(normalized["selectors"])
    return {
        "schema": VALIDATION_SCHEMA,
        "record_type": "SelectorShardValidation",
        "status": "PASS",
        "selector_digest": normalized["selector_digest"],
        "manifest_digest": normalized["manifest_digest"],
        "marker_expression": normalized["marker_expression"],
        "coverage": {
            "exact": selectors == expected,
            "missing": sorted(set(expected) - set(selectors)),
            "unexpected": sorted(set(selectors) - set(expected)),
            "extra": sorted(set(selectors) - set(expected)),
            "duplicates": [],
        },
        "per_process": dict(normalized["per_process"]),
        "aggregate": dict(normalized["aggregate"]),
        "shard_count": len(normalized["shards"]),
        "acceptance_pass": False,
        "pass_credit": False,
    }


def _invalid_harness_receipt(
    normalized: Mapping[str, object],
    *,
    aggregate_elapsed_seconds: float,
    reason: str,
    missing: list[str],
    unexpected: list[str],
    duplicates: list[str],
) -> dict[str, object]:
    return {
        "schema": AGGREGATE_SCHEMA,
        "record_type": "SelectorShardAggregate",
        "status": "INVALID_HARNESS",
        "selector_digest": normalized["selector_digest"],
        "manifest_digest": normalized["manifest_digest"],
        "marker_expression": normalized["marker_expression"],
        "aggregate_elapsed_seconds": aggregate_elapsed_seconds,
        "aggregate_timeout_seconds": normalized["aggregate"]["timeout_seconds"],
        "receipt_coverage": {
            "missing": missing,
            "unexpected": unexpected,
            "duplicates": duplicates,
        },
        "reason": reason,
        "semantic_failure": False,
        "acceptance_pass": False,
        "pass_credit": False,
    }


def record_selector_aggregate(
    manifest: Mapping[str, object],
    rows: Sequence[Mapping[str, object]],
    *,
    aggregate_elapsed_seconds: int | float,
    expected_selectors: Sequence[str] | None = None,
) -> dict[str, object]:
    """Summarize terminal shard receipts without granting semantic pass credit."""

    normalized = _normalize_manifest(manifest, expected_selectors=expected_selectors)
    elapsed = _require_nonnegative_number(aggregate_elapsed_seconds, "aggregate_elapsed_seconds")
    if isinstance(rows, (str, bytes)) or not isinstance(rows, Sequence):
        return _invalid_harness_receipt(
            normalized,
            aggregate_elapsed_seconds=elapsed,
            reason="rows-must-be-a-sequence",
            missing=[str(shard["id"]) for shard in normalized["shards"]],
            unexpected=[],
            duplicates=[],
        )

    expected_ids = [str(shard["id"]) for shard in normalized["shards"]]
    ids: list[str] = []
    normalized_rows: list[dict[str, object]] = []
    malformed_reason: str | None = None
    for index, row in enumerate(rows):
        try:
            terminal = _require_exact_fields(row, _ROW_FIELDS, f"rows[{index}]")
            receipt_id = terminal["id"]
            if not isinstance(receipt_id, str):
                raise SelectorShardError(f"rows[{index}].id must be a string")
            status = terminal["status"]
            if not isinstance(status, str) or status not in _TERMINAL_STATUSES:
                raise SelectorShardError(f"rows[{index}].status is not terminal")
            terminal_elapsed = _require_nonnegative_number(
                terminal["elapsed_seconds"], f"rows[{index}].elapsed_seconds"
            )
        except SelectorShardError as error:
            malformed_reason = str(error)
            break
        ids.append(receipt_id)
        normalized_rows.append(
            {"id": receipt_id, "status": status, "elapsed_seconds": terminal_elapsed}
        )

    duplicates = sorted(receipt_id for receipt_id in set(ids) if ids.count(receipt_id) > 1)
    missing = sorted(set(expected_ids) - set(ids))
    unexpected = sorted(set(ids) - set(expected_ids))
    if malformed_reason is not None or missing or unexpected or duplicates:
        return _invalid_harness_receipt(
            normalized,
            aggregate_elapsed_seconds=elapsed,
            reason=malformed_reason or "terminal-receipts-do-not-match-manifest",
            missing=missing,
            unexpected=unexpected,
            duplicates=duplicates,
        )

    statuses = {str(row["status"]) for row in normalized_rows}
    if "INVALID_HARNESS" in statuses:
        status = "INVALID_HARNESS"
        semantic_failure = False
    elif "FAIL" in statuses:
        status = "FAIL"
        semantic_failure = True
    elif elapsed > int(normalized["aggregate"]["timeout_seconds"]):
        status = "TIMEOUT"
        semantic_failure = False
    elif "TIMEOUT" in statuses:
        status = "TIMEOUT"
        semantic_failure = False
    elif "UNAVAILABLE" in statuses:
        status = "UNAVAILABLE"
        semantic_failure = False
    else:
        status = "PASS"
        semantic_failure = False
    return {
        "schema": AGGREGATE_SCHEMA,
        "record_type": "SelectorShardAggregate",
        "status": status,
        "selector_digest": normalized["selector_digest"],
        "manifest_digest": normalized["manifest_digest"],
        "marker_expression": normalized["marker_expression"],
        "aggregate_elapsed_seconds": elapsed,
        "aggregate_timeout_seconds": normalized["aggregate"]["timeout_seconds"],
        "receipt_coverage": {"missing": [], "unexpected": [], "duplicates": []},
        "rows": sorted(normalized_rows, key=lambda row: str(row["id"])),
        "semantic_failure": semantic_failure,
        "acceptance_pass": False,
        "pass_credit": False,
    }


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SelectorShardError(f"manifest JSON contains duplicate key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_json(value: str) -> None:
    raise SelectorShardError(f"manifest JSON contains non-finite value: {value}")


def load_selector_shard_manifest(path: Path) -> dict[str, Any]:
    """Strict-load a bounded JSON manifest and validate it before process use."""

    if not isinstance(path, Path):
        raise SelectorShardError("manifest path must be a pathlib.Path")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SelectorShardError(f"manifest is unavailable: {type(error).__name__}") from error
    attributes = getattr(metadata, "st_file_attributes", 0)
    if stat.S_ISLNK(metadata.st_mode) or attributes & _REPARSE_POINT or not stat.S_ISREG(metadata.st_mode):
        raise SelectorShardError("manifest path must be a regular non-link file")
    if metadata.st_size > _MAX_MANIFEST_BYTES:
        raise SelectorShardError("manifest exceeds bounded loader size")
    try:
        raw = path.read_bytes()
        decoded = raw.decode("utf-8")
        parsed = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, SelectorShardError) as error:
        if isinstance(error, SelectorShardError):
            raise
        raise SelectorShardError(f"manifest JSON is invalid: {type(error).__name__}") from error
    if not isinstance(parsed, Mapping):
        raise SelectorShardError("manifest JSON root must be an object")
    return _normalize_manifest(parsed)


def _memory_preexec(memory_bytes: int) -> Any | None:
    """Return a POSIX memory limiter, or ``None`` when it cannot be enforced."""

    if os.name != "posix":
        return None
    try:
        import resource
    except ImportError:
        return None
    if not hasattr(resource, "RLIMIT_AS"):
        return None

    def apply_limit() -> None:
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))

    return apply_limit


def _runner_receipt(
    normalized: Mapping[str, object],
    *,
    shard_id: str,
    status: str,
    elapsed_seconds: float,
    exit_code: int | None,
    semantic_failure: bool,
) -> dict[str, object]:
    shard = next(shard for shard in normalized["shards"] if shard["id"] == shard_id)
    limits = shard["limits"]
    return {
        "schema": RUNNER_RECEIPT_SCHEMA,
        "record_type": "SelectorShardRunnerReceipt",
        "id": shard_id,
        "status": status,
        "selector_digest": normalized["selector_digest"],
        "marker_expression": normalized["marker_expression"],
        "elapsed_seconds": round(max(0.0, elapsed_seconds), 6),
        "timeout_seconds": limits["timeout_seconds"],
        "memory_bytes": limits["memory_bytes"],
        "exit_code": exit_code,
        "semantic_failure": semantic_failure,
        "acceptance_pass": False,
        "pass_credit": False,
    }


def run_selector_shard(
    manifest: Mapping[str, object],
    shard_id: str,
    *,
    project_root: Path,
    python_executable: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Run exactly one validated shard, or fail closed when limits are unavailable.

    The subprocess receives the immutable timeout and memory values that were
    bound into the manifest.  No caller-supplied argument can add selectors or
    widen those limits.
    """

    normalized = _normalize_manifest(manifest)
    if not isinstance(shard_id, str):
        raise SelectorShardError("shard_id must be a string")
    if not isinstance(project_root, Path):
        raise SelectorShardError("project_root must be a pathlib.Path")
    try:
        project_metadata = project_root.lstat()
    except OSError as error:
        raise SelectorShardError(f"project_root is unavailable: {type(error).__name__}") from error
    if not stat.S_ISDIR(project_metadata.st_mode):
        raise SelectorShardError("project_root must be a directory")
    selected_shards = [shard for shard in normalized["shards"] if shard["id"] == shard_id]
    if len(selected_shards) != 1:
        raise SelectorShardError("shard_id is not present in the manifest")
    shard = selected_shards[0]
    limits = shard["limits"]
    timeout_seconds = int(limits["timeout_seconds"])
    memory_bytes = int(limits["memory_bytes"])
    preexec = _memory_preexec(memory_bytes)
    if preexec is None:
        return _runner_receipt(
            normalized,
            shard_id=shard_id,
            status="UNAVAILABLE",
            elapsed_seconds=0.0,
            exit_code=None,
            semantic_failure=False,
        )

    executable = sys.executable if python_executable is None else python_executable
    if not isinstance(executable, str) or not executable or executable != executable.strip():
        raise SelectorShardError("python_executable must be a non-empty string")
    command = [
        executable,
        "-m",
        "pytest",
        "-q",
        "-m",
        str(normalized["marker_expression"]),
        "--",
        *(str(selector) for selector in shard["selectors"]),
    ]
    child_environment = dict(os.environ)
    child_environment.pop("PYTEST_ADDOPTS", None)
    if environment is not None:
        if not isinstance(environment, Mapping):
            raise SelectorShardError("environment must be a string mapping")
        for key, value in environment.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise SelectorShardError("environment must be a string mapping")
            if key == "PYTEST_ADDOPTS":
                raise SelectorShardError("environment cannot alter immutable pytest arguments")
            child_environment[key] = value

    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=str(project_root),
            env=child_environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            preexec_fn=preexec,
        )
    except subprocess.TimeoutExpired:
        return _runner_receipt(
            normalized,
            shard_id=shard_id,
            status="TIMEOUT",
            elapsed_seconds=time.monotonic() - started,
            exit_code=None,
            semantic_failure=False,
        )
    except OSError:
        return _runner_receipt(
            normalized,
            shard_id=shard_id,
            status="UNAVAILABLE",
            elapsed_seconds=time.monotonic() - started,
            exit_code=None,
            semantic_failure=False,
        )

    if completed.returncode == 0:
        status = "PASS"
        semantic_failure = False
    else:
        status = "FAIL"
        semantic_failure = True
    return _runner_receipt(
        normalized,
        shard_id=shard_id,
        status=status,
        elapsed_seconds=time.monotonic() - started,
        exit_code=completed.returncode,
        semantic_failure=semantic_failure,
    )


__all__ = [
    "AGGREGATE_SCHEMA",
    "MANIFEST_SCHEMA",
    "RUNNER_RECEIPT_SCHEMA",
    "SelectorShardError",
    "VALIDATION_SCHEMA",
    "build_selector_shard_manifest",
    "load_selector_shard_manifest",
    "record_selector_aggregate",
    "run_selector_shard",
    "validate_selector_shard_manifest",
]
