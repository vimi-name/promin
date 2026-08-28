"""Deterministic selector sharding with immutable per-process limits.

The module creates and checks data-only shard manifests.  ``run_selector_shard``
is intentionally separate from static admission: it is a bounded dynamic child
process route.  Timeout remains process-enforced, while memory enforcement is
reported as either process-local POSIX ``RLIMIT_AS`` or host responsibility.
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
import threading
import time
from typing import Any, Final

from .canonical import canonical_bytes, digest_bytes, digest_value
from .version import standard_version


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
_MAX_CAPTURE_BYTES: Final = 1 * 1024 * 1024
_REPARSE_POINT: Final = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
_AGGREGATE_EXECUTION_SCHEMA: Final = "promin.selector-shard-aggregate-execution.v1"
_FIXED_SELECTOR_SET_ID: Final = "standard-alpha4-non-scale-v1"
_FIXED_MARKER_EXPRESSION: Final = "not scale"
_FIXED_SELECTOR_COUNT: Final = 125
_FIXED_SHARD_IDS: Final = (
    "core-state",
    "canonical-init",
    "experience-portability",
    "reconciliation-paths",
    "eventstore-derived-storage",
    "alpha4-policies",
    "alpha4-policy-hardening",
    "service-distribution",
    "client-evidence-publication",
    "verified-query",
    "verified-query-lifecycle",
    "package-validation",
    "package-integrity",
    "package-execution",
    "heavy-hardening",
    "scale-search",
)
_FIXED_PER_PROCESS_LIMITS: Final = {
    "timeout_seconds": 600,
    "memory_bytes": 1073741824,
}
_FIXED_AGGREGATE_TIMEOUT_SECONDS: Final = 9600
_FIXED_PLAN_RELATIVE_PATH: Final = Path("tests") / "ALPHA4_TEST_SHARDS.json"
_FIXED_WINDOWS_EXCLUDED_SELECTORS: Final = frozenset(
    {"tests/test_heavy_linux_model.py"}
)
_RECEIPT_FIELDS: Final = frozenset(
    {
        "schema", "record_type", "id", "shard_order", "status", "execution_state",
        "manifest_digest", "selector_digest", "marker_expression", "elapsed_seconds",
        "timeout_seconds", "memory_bytes", "memory_enforcement", "exit_code",
        "stdout_path", "stdout_bytes", "stdout_sha256", "stderr_path", "stderr_bytes",
        "stderr_sha256", "semantic_failure", "reason", "acceptance_pass",
        "product_acceptance_pass", "performance_acceptance", "pass_credit", "proxy_acceptance",
    }
)
_EXECUTION_FIELDS: Final = frozenset(
    {
        "schema", "record_type", "status", "platform", "manifest_digest", "selector_digest",
        "marker_expression", "candidate_binding_digest", "standard_candidate_binding",
        "source_closure", "aggregate", "files", "acceptance_pass", "product_acceptance_pass",
        "performance_acceptance", "pass_credit", "proxy_acceptance",
    }
)


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
    elif elapsed >= int(normalized["aggregate"]["timeout_seconds"]):
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
    memory_enforcement: str,
) -> dict[str, object]:
    if memory_enforcement not in {"process-rlimit-as", "host-responsibility"}:
        raise SelectorShardError("memory_enforcement must be a closed value")
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
        "memory_enforcement": memory_enforcement,
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
    """Run exactly one validated shard with bounded timeout and declared limits.

    The subprocess receives the immutable timeout and memory values that were
    bound into the manifest.  Timeout is enforced by the parent process.  When
    a POSIX address-space limiter is unavailable, execution continues and the
    receipt records host responsibility for the memory budget.  No
    caller-supplied argument can add selectors or widen those limits.
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
    memory_enforcement = (
        "process-rlimit-as" if preexec is not None else "host-responsibility"
    )

    executable = sys.executable if python_executable is None else python_executable
    if not isinstance(executable, str) or not executable or executable != executable.strip():
        raise SelectorShardError("python_executable must be a non-empty string")
    command = [
        executable,
        "-B",
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "-q",
        "-m",
        str(normalized["marker_expression"]),
        "--",
        *(str(selector) for selector in shard["selectors"]),
    ]
    child_environment = dict(os.environ)
    child_environment.pop("PYTEST_ADDOPTS", None)
    child_environment["PYTHONDONTWRITEBYTECODE"] = "1"
    if environment is not None:
        if not isinstance(environment, Mapping):
            raise SelectorShardError("environment must be a string mapping")
        for key, value in environment.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise SelectorShardError("environment must be a string mapping")
            if key == "PYTEST_ADDOPTS":
                raise SelectorShardError("environment cannot alter immutable pytest arguments")
            child_environment[key] = value

    run_options: dict[str, object] = {}
    if preexec is not None:
        run_options["preexec_fn"] = preexec

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
            **run_options,
        )
    except subprocess.TimeoutExpired:
        return _runner_receipt(
            normalized,
            shard_id=shard_id,
            status="TIMEOUT",
            elapsed_seconds=time.monotonic() - started,
            exit_code=None,
            semantic_failure=False,
            memory_enforcement=memory_enforcement,
        )
    except OSError:
        return _runner_receipt(
            normalized,
            shard_id=shard_id,
            status="UNAVAILABLE",
            elapsed_seconds=time.monotonic() - started,
            exit_code=None,
            semantic_failure=False,
            memory_enforcement=memory_enforcement,
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
        memory_enforcement=memory_enforcement,
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_file(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SelectorShardError(f"{label} is unavailable: {type(error).__name__}") from error
    attributes = getattr(metadata, "st_file_attributes", 0)
    if stat.S_ISLNK(metadata.st_mode) or attributes & _REPARSE_POINT or not stat.S_ISREG(metadata.st_mode):
        raise SelectorShardError(f"{label} must be a regular non-link file")
    return path


def _validate_directory_ancestors(path: Path, label: str) -> None:
    current = path.absolute()
    while True:
        try:
            metadata = current.lstat()
        except OSError as error:
            raise SelectorShardError(f"{label} ancestor is unavailable") from error
        attributes = getattr(metadata, "st_file_attributes", 0)
        if stat.S_ISLNK(metadata.st_mode):
            raise SelectorShardError(f"{label} ancestor is a symlink")
        if attributes & _REPARSE_POINT:
            raise SelectorShardError(f"{label} ancestor is a reparse point")
        if not stat.S_ISDIR(metadata.st_mode):
            raise SelectorShardError(f"{label} ancestor must be a directory")
        if current == current.parent:
            return
        current = current.parent


def _test_manifest_rows(project_root: Path) -> list[dict[str, object]]:
    tests_root = project_root / "tests"
    try:
        metadata = tests_root.lstat()
    except OSError as error:
        raise SelectorShardError(f"tests directory is unavailable: {type(error).__name__}") from error
    attributes = getattr(metadata, "st_file_attributes", 0)
    if stat.S_ISLNK(metadata.st_mode) or attributes & _REPARSE_POINT or not stat.S_ISDIR(metadata.st_mode):
        raise SelectorShardError("tests directory must be a regular non-link directory")
    rows: list[dict[str, object]] = []
    try:
        entries = sorted(tests_root.iterdir(), key=lambda item: item.name)
    except OSError as error:
        raise SelectorShardError("tests directory cannot be enumerated") from error
    for path in entries:
        if not path.name.startswith("test_") or path.suffix != ".py":
            continue
        _regular_file(path, f"test source {path.name}")
        rows.append({
            "path": f"tests/{path.name}",
            "sha256": _sha256_file(path),
            "size": path.stat().st_size,
        })
    if not rows:
        raise SelectorShardError("tests/test_*.py closure is empty")
    return rows


def _source_closure(project_root: Path, candidate: Mapping[str, object]) -> dict[str, object]:
    observed = _source_observation(project_root)
    if candidate.get("package_manifest_digest") != observed["manifest_sha256"]:
        raise SelectorShardError("local MANIFEST.json digest differs from candidate binding")
    if candidate.get("checksums_digest") != observed["checksums_sha256"]:
        raise SelectorShardError("local SHA256SUMS.txt digest differs from candidate binding")
    if candidate.get("test_manifest_digest") != observed["test_manifest_digest"]:
        raise SelectorShardError("current tests/test_*.py digest differs from candidate binding")
    return observed


def _source_observation(project_root: Path) -> dict[str, object]:
    manifest_path = _regular_file(project_root / "MANIFEST.json", "MANIFEST.json")
    checksums_path = _regular_file(project_root / "SHA256SUMS.txt", "SHA256SUMS.txt")
    rows = _test_manifest_rows(project_root)
    manifest_digest = _sha256_file(manifest_path)
    checksums_digest = _sha256_file(checksums_path)
    tests_digest = digest_value(rows)
    return {
        "manifest_sha256": manifest_digest,
        "checksums_sha256": checksums_digest,
        "test_manifest_digest": tests_digest,
        "test_rows": rows,
    }


def _validated_aggregate_inputs(
    manifest: Mapping[str, object],
    *,
    project_root: Path,
    candidate_binding: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, object], Path]:
    if os.name != "nt":
        raise SelectorShardError("selector aggregate execution is Windows-only")
    normalized = _normalize_manifest(manifest)
    if normalized["selector_set_id"] != _FIXED_SELECTOR_SET_ID:
        raise SelectorShardError(
            f"aggregate selector_set_id must be {_FIXED_SELECTOR_SET_ID}"
        )
    if normalized["marker_expression"] != _FIXED_MARKER_EXPRESSION:
        raise SelectorShardError(
            f"aggregate marker_expression must be {_FIXED_MARKER_EXPRESSION}"
        )
    if normalized["selector_count"] != _FIXED_SELECTOR_COUNT:
        raise SelectorShardError(
            f"aggregate manifest must contain exactly {_FIXED_SELECTOR_COUNT} selectors"
        )
    shards = normalized["shards"]
    if len(shards) != len(_FIXED_SHARD_IDS):
        raise SelectorShardError(
            f"aggregate manifest must contain exactly {len(_FIXED_SHARD_IDS)} shards"
        )
    shard_ids = [str(shard["id"]) for shard in shards]
    if shard_ids != list(_FIXED_SHARD_IDS):
        raise SelectorShardError("aggregate shard IDs and order must match the fixed protocol")
    if normalized["per_process"] != _FIXED_PER_PROCESS_LIMITS:
        raise SelectorShardError("aggregate per-process limits must match the fixed protocol")
    if normalized["aggregate"] != {"timeout_seconds": _FIXED_AGGREGATE_TIMEOUT_SECONDS}:
        raise SelectorShardError("aggregate timeout must match the fixed protocol")
    for shard in shards:
        if shard["limits"] != _FIXED_PER_PROCESS_LIMITS:
            raise SelectorShardError("aggregate shard limits must match the fixed protocol")
    if not isinstance(project_root, Path):
        raise SelectorShardError("project_root must be a pathlib.Path")
    _validate_directory_ancestors(project_root, "project_root")
    protocol_path = project_root / _FIXED_PLAN_RELATIVE_PATH
    try:
        protocol_manifest = load_selector_shard_manifest(
            _regular_file(protocol_path, "canonical selector shard plan")
        )
    except SelectorShardError as error:
        raise SelectorShardError(f"canonical selector shard plan is invalid: {error}") from error
    if protocol_manifest != normalized:
        raise SelectorShardError(
            "aggregate manifest must exactly match tests/ALPHA4_TEST_SHARDS.json"
        )
    try:
        from .evidence import validate_standard_release_candidate_binding
        candidate = validate_standard_release_candidate_binding(candidate_binding)
    except Exception as error:
        raise SelectorShardError(f"candidate binding is invalid: {error}") from error
    if candidate.get("version") != standard_version():
        raise SelectorShardError(
            "candidate binding version must match current standard version"
        )
    source = _source_closure(project_root, candidate)
    source_rows = source["test_rows"]
    source_paths = {str(row["path"]) for row in source_rows}
    missing_exclusions = sorted(_FIXED_WINDOWS_EXCLUDED_SELECTORS - source_paths)
    if missing_exclusions:
        raise SelectorShardError(
            "Windows selector exclusion is absent from source closure: "
            f"{missing_exclusions}"
        )
    expected = [
        str(row["path"])
        for row in source_rows
        if str(row["path"]) not in _FIXED_WINDOWS_EXCLUDED_SELECTORS
    ]
    _normalize_manifest(manifest, expected_selectors=expected)
    return normalized, source, candidate


def _safe_evidence_root(evidence_root: Path, project_root: Path, *, create: bool) -> Path:
    if not isinstance(evidence_root, Path):
        raise SelectorShardError("evidence_root must be a pathlib.Path")
    project = project_root.absolute()
    selected = evidence_root.absolute()
    try:
        overlaps = selected == project or selected.is_relative_to(project) or project.is_relative_to(selected)
    except ValueError:
        overlaps = False
    if overlaps:
        raise SelectorShardError("evidence_root must be outside and non-overlapping with project_root")
    current = selected.parent
    while True:
        try:
            metadata = current.lstat()
        except OSError as error:
            raise SelectorShardError("evidence_root parent is unavailable") from error
        attributes = getattr(metadata, "st_file_attributes", 0)
        if stat.S_ISLNK(metadata.st_mode) or attributes & _REPARSE_POINT or not stat.S_ISDIR(metadata.st_mode):
            raise SelectorShardError("evidence_root parent must contain no links or reparse points")
        if current == current.parent:
            break
        current = current.parent
    if create and (selected.exists() or selected.is_symlink()):
        raise SelectorShardError("evidence_root must be absent and create-only")
    if not create and (not selected.exists() or selected.is_symlink()):
        raise SelectorShardError("evidence_root must be an existing regular directory")
    if create:
        selected.mkdir()
    return selected


def _write_create_only(path: Path, payload: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise SelectorShardError(f"cannot create evidence file {path.name}") from error


def _load_evidence_json(path: Path) -> dict[str, object]:
    _regular_file(path, "evidence JSON")
    try:
        raw = path.read_bytes()
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json,
        )
        if not isinstance(parsed, dict) or canonical_bytes(parsed) != raw:
            raise SelectorShardError("evidence JSON is not canonical")
        return parsed
    except SelectorShardError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SelectorShardError("evidence JSON is invalid") from error


def _aggregate_receipt(
    normalized: Mapping[str, object],
    shard: Mapping[str, object],
    *,
    shard_order: int,
    status: str,
    execution_state: str,
    elapsed_seconds: float,
    timeout_seconds: int,
    exit_code: int | None,
    stdout: bytes,
    stderr: bytes,
    reason: str | None = None,
) -> dict[str, object]:
    if len(stdout) > _MAX_CAPTURE_BYTES or len(stderr) > _MAX_CAPTURE_BYTES:
        status, execution_state = "INVALID_HARNESS", "invalid"
        reason = "; ".join(
            item for item in (reason, "log exceeds 1 MiB capture limit") if item
        )
        stdout = stdout[:_MAX_CAPTURE_BYTES]
        stderr = stderr[:_MAX_CAPTURE_BYTES]
    try:
        stdout.decode("utf-8", errors="strict")
        stderr.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        status, execution_state = "INVALID_HARNESS", "invalid"
        reason = "; ".join(item for item in (reason, "child output is not UTF-8") if item)
    return {
        "schema": RUNNER_RECEIPT_SCHEMA,
        "record_type": "SelectorShardRunnerReceipt",
        "id": shard["id"],
        "shard_order": shard_order,
        "status": status,
        "execution_state": execution_state,
        "manifest_digest": normalized["manifest_digest"],
        "selector_digest": normalized["selector_digest"],
        "marker_expression": normalized["marker_expression"],
        "elapsed_seconds": round(max(0.0, elapsed_seconds), 6),
        "timeout_seconds": int(shard["limits"]["timeout_seconds"]),
        "memory_bytes": int(shard["limits"]["memory_bytes"]),
        "memory_enforcement": "host-responsibility",
        "exit_code": exit_code,
        "stdout_path": f"shards/{shard['id']}/stdout.log",
        "stdout_bytes": len(stdout),
        "stdout_sha256": digest_bytes(stdout),
        "stderr_path": f"shards/{shard['id']}/stderr.log",
        "stderr_bytes": len(stderr),
        "stderr_sha256": digest_bytes(stderr),
        "semantic_failure": status == "FAIL",
        "reason": reason,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "performance_acceptance": False,
        "pass_credit": False,
        "proxy_acceptance": False,
    }, stdout, stderr


def _execute_aggregate_shard(
    normalized: Mapping[str, object], shard: Mapping[str, object], *, project_root: Path, shard_dir: Path, timeout_seconds: float,
    python_executable: str | None,
) -> tuple[dict[str, object], bytes, bytes]:
    executable = sys.executable if python_executable is None else python_executable
    if not isinstance(executable, str) or not executable or executable != executable.strip():
        raise SelectorShardError("python_executable must be a non-empty string")
    command = [executable, "-B", "-m", "pytest", "-p", "no:cacheprovider", "-q", "-m", str(normalized["marker_expression"]), "--", *(str(item) for item in shard["selectors"])]
    environment = dict(os.environ)
    environment.pop("PYTEST_ADDOPTS", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    started = time.monotonic()
    class BoundedReader:
        def __init__(self, stream: Any) -> None:
            self.stream = stream
            self.data = bytearray()
            self.overflow = False
            self.error: str | None = None

        def run(self) -> None:
            try:
                while True:
                    chunk = self.stream.read(64 * 1024)
                    if not chunk:
                        return
                    remaining = _MAX_CAPTURE_BYTES - len(self.data)
                    if remaining <= 0:
                        self.overflow = True
                        continue
                    if len(chunk) > remaining:
                        self.data.extend(chunk[:remaining])
                        self.overflow = True
                    else:
                        self.data.extend(chunk)
            except BaseException as error:
                self.error = f"{type(error).__name__}: {error}"

    def terminate_bounded(process: Any) -> tuple[bool, str | None]:
        errors: list[str] = []
        try:
            process.terminate()
        except BaseException as error:
            errors.append(f"terminate {type(error).__name__}: {error}")
        try:
            process.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except BaseException as error:
                errors.append(f"kill {type(error).__name__}: {error}")
            try:
                process.wait(timeout=0.25)
            except subprocess.TimeoutExpired:
                pass
            except BaseException as error:
                errors.append(f"kill-wait {type(error).__name__}: {error}")
        except BaseException as error:
            errors.append(f"wait {type(error).__name__}: {error}")
            try:
                process.kill()
            except BaseException as kill_error:
                errors.append(f"kill {type(kill_error).__name__}: {kill_error}")
            try:
                process.wait(timeout=0.25)
            except BaseException as wait_error:
                errors.append(f"kill-wait {type(wait_error).__name__}: {wait_error}")
        try:
            contained = process.poll() is not None
        except BaseException as error:
            errors.append(f"poll {type(error).__name__}: {error}")
            contained = False
        if not contained:
            errors.append("child containment was not confirmed")
        return contained, "; ".join(errors) if errors else None

    try:
        process = subprocess.Popen(command, cwd=str(project_root), env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    except OSError as error:
        return _aggregate_receipt(normalized, shard, shard_order=0, status="UNAVAILABLE", execution_state="unavailable", elapsed_seconds=time.monotonic() - started, timeout_seconds=int(shard["limits"]["timeout_seconds"]), exit_code=None, stdout=b"", stderr=b"", reason=type(error).__name__)
    stdout_reader = BoundedReader(process.stdout)
    stderr_reader = BoundedReader(process.stderr)
    stdout_thread = threading.Thread(
        target=stdout_reader.run, name="promin-selector-stdout", daemon=True
    )
    stderr_thread = threading.Thread(
        target=stderr_reader.run, name="promin-selector-stderr", daemon=True
    )
    timed_out = False
    containment_requested = False
    terminated = True
    termination_reason: str | None = None
    operation_errors: list[str] = []

    def request_containment() -> None:
        nonlocal containment_requested, terminated, termination_reason
        containment_requested = True
        try:
            terminated, termination_reason = terminate_bounded(process)
        except BaseException as error:
            terminated = False
            operation_errors.append(
                f"containment {type(error).__name__}: {error}"
            )

    try:
        stdout_thread.start()
        stderr_thread.start()
        while True:
            try:
                returncode = process.poll()
            except BaseException as error:
                operation_errors.append(f"poll {type(error).__name__}: {error}")
                request_containment()
                break
            if returncode is not None:
                break
            if stdout_reader.error or stderr_reader.error:
                request_containment()
                break
            if stdout_reader.overflow or stderr_reader.overflow:
                request_containment()
                break
            remaining = timeout_seconds - (time.monotonic() - started)
            if remaining <= 0:
                timed_out = True
                request_containment()
                break
            time.sleep(min(0.01, remaining))
    except BaseException as error:
        operation_errors.append(f"child loop {type(error).__name__}: {error}")
        request_containment()

    reader_threads = (
        ("stdout", stdout_thread), ("stderr", stderr_thread)
    )

    def join_readers() -> tuple[list[str], list[str]]:
        alive: list[str] = []
        errors: list[str] = []
        for stream_name, reader_thread in reader_threads:
            try:
                reader_thread.join(timeout=0.5)
            except BaseException as error:
                errors.append(
                    f"{stream_name} reader join {type(error).__name__}: {error}"
                )
            try:
                if reader_thread.is_alive():
                    alive.append(stream_name)
            except BaseException as error:
                errors.append(
                    f"{stream_name} reader state {type(error).__name__}: {error}"
                )
                alive.append(stream_name)
        return alive, errors

    reader_threads_alive, reader_join_errors = join_readers()
    operation_errors.extend(reader_join_errors)
    cleanup_fallback = bool(reader_join_errors or reader_threads_alive or not terminated)
    if cleanup_fallback:
        if reader_threads_alive:
            operation_errors.append(
                "child stream reader remained alive after bounded drain; parent handles were closed"
            )
        elif not terminated:
            operation_errors.append(
                "child containment was not confirmed before parent handles were closed"
            )
        for stream_name in ("stdout", "stderr"):
            try:
                getattr(process, stream_name).close()
            except BaseException as error:
                operation_errors.append(
                    f"close {stream_name} {type(error).__name__}: {error}"
                )
        reader_threads_alive, second_join_errors = join_readers()
        operation_errors.extend(second_join_errors)

    stdout = bytes(stdout_reader.data)
    stderr = bytes(stderr_reader.data)
    reasons = list(operation_errors)
    if termination_reason:
        reasons.append(termination_reason)
    if stdout_reader.error or stderr_reader.error:
        reasons.append(
            f"child stream reader failed: {stdout_reader.error or stderr_reader.error}"
        )
    if stdout_reader.overflow or stderr_reader.overflow:
        reasons.append("child stream output exceeded 1 MiB capture limit")
    if reader_threads_alive:
        reasons.append(
            "child stream reader did not complete within bounded cleanup: "
            + ",".join(reader_threads_alive)
        )
    if containment_requested and not terminated:
        reasons.append("child termination or stream cleanup was not contained")

    try:
        process_returncode = process.returncode
    except BaseException as error:
        process_returncode = None
        reasons.append(f"returncode {type(error).__name__}: {error}")

    elapsed = time.monotonic() - started
    if reasons:
        receipt, stdout, stderr = _aggregate_receipt(
            normalized,
            shard,
            shard_order=0,
            status="INVALID_HARNESS",
            execution_state="invalid",
            elapsed_seconds=elapsed,
            timeout_seconds=int(shard["limits"]["timeout_seconds"]),
            exit_code=process_returncode,
            stdout=stdout,
            stderr=stderr,
            reason="; ".join(dict.fromkeys(reasons)),
        )
    elif timed_out:
        receipt, stdout, stderr = _aggregate_receipt(
            normalized,
            shard,
            shard_order=0,
            status="TIMEOUT",
            execution_state="timed-out",
            elapsed_seconds=elapsed,
            timeout_seconds=int(shard["limits"]["timeout_seconds"]),
            exit_code=None,
            stdout=stdout,
            stderr=stderr,
            reason="child timeout exceeded",
        )
    else:
        status = "PASS" if process_returncode == 0 else "FAIL"
        receipt, stdout, stderr = _aggregate_receipt(
            normalized,
            shard,
            shard_order=0,
            status=status,
            execution_state="completed",
            elapsed_seconds=elapsed,
            timeout_seconds=int(shard["limits"]["timeout_seconds"]),
            exit_code=process_returncode,
            stdout=stdout,
            stderr=stderr,
        )
    return receipt, stdout, stderr


def run_selector_aggregate(
    manifest: Mapping[str, object], *, project_root: Path, evidence_root: Path,
    candidate_binding: Mapping[str, object], python_executable: str | None = None,
) -> dict[str, object]:
    """Execute one sequential, Windows-only aggregate and persist its evidence."""
    normalized, source_before, candidate = _validated_aggregate_inputs(manifest, project_root=project_root, candidate_binding=candidate_binding)
    output = _safe_evidence_root(evidence_root, project_root, create=True)
    started = time.monotonic()
    deadline = started + float(normalized["aggregate"]["timeout_seconds"])
    receipts: list[dict[str, object]] = []
    shard_dirs: dict[str, Path] = {}
    for shard in normalized["shards"]:
        shard_dir = output / "shards" / str(shard["id"])
        shard_dir.mkdir(parents=True)
        shard_dirs[str(shard["id"])] = shard_dir
    for order, shard in enumerate(normalized["shards"], start=1):
        remaining = deadline - time.monotonic()
        shard_dir = shard_dirs[str(shard["id"])]
        if remaining <= 0:
            receipt, stdout, stderr = _aggregate_receipt(normalized, shard, shard_order=order, status="TIMEOUT", execution_state="not-started", elapsed_seconds=0.0, timeout_seconds=int(shard["limits"]["timeout_seconds"]), exit_code=None, stdout=b"", stderr=b"", reason="aggregate deadline expired before spawn")
        else:
            child_timeout = min(float(shard["limits"]["timeout_seconds"]), remaining)
            if child_timeout <= 0:
                receipt, stdout, stderr = _aggregate_receipt(normalized, shard, shard_order=order, status="TIMEOUT", execution_state="not-started", elapsed_seconds=0.0, timeout_seconds=int(shard["limits"]["timeout_seconds"]), exit_code=None, stdout=b"", stderr=b"", reason="aggregate deadline expired before spawn")
            else:
                receipt, stdout, stderr = _execute_aggregate_shard(normalized, shard, project_root=project_root, shard_dir=shard_dir, timeout_seconds=child_timeout, python_executable=python_executable)
            receipt["shard_order"] = order
        _write_create_only(shard_dir / "stdout.log", stdout)
        _write_create_only(shard_dir / "stderr.log", stderr)
        _write_create_only(shard_dir / "receipt.json", canonical_bytes(receipt))
        receipts.append(receipt)
    try:
        source_after = _source_observation(project_root)
    except SelectorShardError as error:
        source_after = {"observation_error": str(error)}
    aggregate = _derive_aggregate_from_receipts(
        normalized,
        receipts,
        aggregate_elapsed_seconds=time.monotonic() - started,
    )
    if source_after != source_before:
        aggregate = {
            **aggregate,
            "status": "INVALID_HARNESS",
            "reason": "source closure drifted during aggregate execution",
            "semantic_failure": False,
        }
    files = sorted(["execution.json"] + [f"shards/{shard['id']}/{name}" for shard in normalized["shards"] for name in ("receipt.json", "stdout.log", "stderr.log")])
    execution = {
        "schema": _AGGREGATE_EXECUTION_SCHEMA,
        "record_type": "SelectorShardAggregateExecution",
        "status": aggregate["status"],
        "platform": "windows",
        "manifest_digest": normalized["manifest_digest"],
        "selector_digest": normalized["selector_digest"],
        "marker_expression": normalized["marker_expression"],
        "candidate_binding_digest": candidate["candidate_binding_digest"],
        "standard_candidate_binding": candidate,
        "source_closure": source_after,
        "aggregate": aggregate,
        "files": files,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "performance_acceptance": False,
        "pass_credit": False,
        "proxy_acceptance": False,
    }
    _write_create_only(output / "execution.json", canonical_bytes(execution))
    return execution


def _expected_evidence_files(normalized: Mapping[str, object]) -> set[str]:
    return {"execution.json", *(f"shards/{shard['id']}/{name}" for shard in normalized["shards"] for name in ("receipt.json", "stdout.log", "stderr.log"))}


def _derive_aggregate_from_receipts(
    normalized: Mapping[str, object],
    receipts: Sequence[Mapping[str, object]],
    *,
    aggregate_elapsed_seconds: int | float,
) -> dict[str, object]:
    """Derive the persisted aggregate identically for execution and validation."""
    rows = [
        {
            "id": row["id"],
            "status": row["status"],
            "elapsed_seconds": row["elapsed_seconds"],
        }
        for row in receipts
    ]
    aggregate = record_selector_aggregate(
        normalized,
        rows,
        aggregate_elapsed_seconds=aggregate_elapsed_seconds,
    )
    invalid_reasons = [
        str(row["reason"])
        for row in receipts
        if row.get("status") == "INVALID_HARNESS" and row.get("reason")
    ]
    if invalid_reasons:
        aggregate = {**aggregate, "reason": invalid_reasons[0]}
    return aggregate


def _walk_evidence_files(root: Path) -> set[str]:
    found: set[str] = set()

    def raise_scan_error(error: OSError) -> None:
        raise SelectorShardError(f"evidence closure cannot be scanned: {error}") from error

    for current, directories, names in os.walk(
        root, followlinks=False, onerror=raise_scan_error
    ):
        current_path = Path(current)
        for name in [*directories, *names]:
            path = current_path / name
            metadata = path.lstat()
            attributes = getattr(metadata, "st_file_attributes", 0)
            if stat.S_ISLNK(metadata.st_mode) or attributes & _REPARSE_POINT:
                raise SelectorShardError("evidence closure contains link or reparse point")
            if name in directories:
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise SelectorShardError("evidence closure contains a non-regular file")
            found.add(path.relative_to(root).as_posix())
    return found


def validate_selector_aggregate_evidence(
    manifest: Mapping[str, object], *, project_root: Path, evidence_root: Path,
    candidate_binding: Mapping[str, object],
) -> dict[str, object]:
    """Independently validate a persisted aggregate closure on Windows."""
    normalized, source, candidate = _validated_aggregate_inputs(manifest, project_root=project_root, candidate_binding=candidate_binding)
    root = _safe_evidence_root(evidence_root, project_root, create=False)
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise SelectorShardError("evidence_root is unavailable") from error
    root_attributes = getattr(root_metadata, "st_file_attributes", 0)
    if stat.S_ISLNK(root_metadata.st_mode) or root_attributes & _REPARSE_POINT or not stat.S_ISDIR(root_metadata.st_mode):
        raise SelectorShardError("evidence_root must be an existing regular directory")
    expected_files = _expected_evidence_files(normalized)
    if _walk_evidence_files(root) != expected_files:
        raise SelectorShardError("persisted evidence file closure is not exact")
    execution = _load_evidence_json(root / "execution.json")
    if execution.get("schema") != _AGGREGATE_EXECUTION_SCHEMA or execution.get("record_type") != "SelectorShardAggregateExecution":
        raise SelectorShardError("execution record schema is invalid")
    if set(execution) != _EXECUTION_FIELDS:
        raise SelectorShardError("execution fields are not exact")
    if execution.get("platform") != "windows" or execution.get("manifest_digest") != normalized["manifest_digest"] or execution.get("selector_digest") != normalized["selector_digest"] or type(execution.get("marker_expression")) is not str or execution.get("marker_expression") != normalized["marker_expression"]:
        raise SelectorShardError("execution marker or identity does not match manifest")
    if execution.get("candidate_binding_digest") != candidate["candidate_binding_digest"] or execution.get("standard_candidate_binding") != candidate or execution.get("source_closure") != source:
        raise SelectorShardError("candidate or source closure does not match current inputs")
    if execution.get("files") != sorted(expected_files):
        raise SelectorShardError("execution file closure is not canonical")
    receipts: list[dict[str, object]] = []
    for order, shard in enumerate(normalized["shards"], start=1):
        shard_dir = root / "shards" / str(shard["id"])
        receipt = _load_evidence_json(shard_dir / "receipt.json")
        if set(receipt) != _RECEIPT_FIELDS:
            raise SelectorShardError("receipt fields are not exact")
        if receipt.get("schema") != RUNNER_RECEIPT_SCHEMA or receipt.get("record_type") != "SelectorShardRunnerReceipt" or receipt.get("marker_expression") != normalized["marker_expression"]:
            raise SelectorShardError("receipt schema, record type, or marker is invalid")
        if not isinstance(receipt.get("id"), str) or not isinstance(receipt.get("shard_order"), int) or isinstance(receipt.get("shard_order"), bool):
            raise SelectorShardError("receipt identity types are invalid")
        _require_nonnegative_number(receipt.get("elapsed_seconds"), "receipt.elapsed_seconds")
        if not isinstance(receipt.get("status"), str) or not isinstance(receipt.get("execution_state"), str):
            raise SelectorShardError("receipt status types are invalid")
        _require_digest(receipt.get("manifest_digest"), "receipt.manifest_digest")
        _require_digest(receipt.get("selector_digest"), "receipt.selector_digest")
        if not isinstance(receipt.get("timeout_seconds"), int) or isinstance(receipt.get("timeout_seconds"), bool) or receipt["timeout_seconds"] <= 0 or not isinstance(receipt.get("memory_bytes"), int) or isinstance(receipt.get("memory_bytes"), bool) or receipt["memory_bytes"] <= 0:
            raise SelectorShardError("receipt limits types are invalid")
        exit_code = receipt.get("exit_code")
        if exit_code is not None and (not isinstance(exit_code, int) or isinstance(exit_code, bool)):
            raise SelectorShardError("receipt exit_code type is invalid")
        if not isinstance(receipt.get("semantic_failure"), bool) or (receipt.get("reason") is not None and not isinstance(receipt.get("reason"), str)):
            raise SelectorShardError("receipt semantic fields are invalid")
        if receipt.get("id") != shard["id"] or receipt.get("shard_order") != order or receipt.get("manifest_digest") != normalized["manifest_digest"] or receipt.get("selector_digest") != normalized["selector_digest"]:
            raise SelectorShardError("receipt identity or order does not match manifest")
        if receipt.get("timeout_seconds") != shard["limits"]["timeout_seconds"] or receipt.get("memory_bytes") != shard["limits"]["memory_bytes"] or receipt.get("memory_enforcement") != "host-responsibility":
            raise SelectorShardError("receipt limits or memory responsibility are invalid")
        status = receipt.get("status")
        execution_state = receipt.get("execution_state")
        exit_code = receipt.get("exit_code")
        semantic_failure = receipt.get("semantic_failure")
        reason = receipt.get("reason")
        valid_state = (
            (status == "PASS" and execution_state == "completed" and exit_code == 0 and semantic_failure is False and reason is None)
            or (status == "FAIL" and execution_state == "completed" and isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code != 0 and semantic_failure is True and reason is None)
            or (status == "TIMEOUT" and execution_state in {"timed-out", "not-started"} and exit_code is None and semantic_failure is False and isinstance(reason, str) and bool(reason))
            or (status == "UNAVAILABLE" and execution_state == "unavailable" and exit_code is None and semantic_failure is False and isinstance(reason, str) and bool(reason))
            or (status == "INVALID_HARNESS" and execution_state == "invalid" and semantic_failure is False and isinstance(reason, str) and bool(reason))
        )
        if not valid_state:
            raise SelectorShardError("receipt state is inconsistent")
        for stream in ("stdout", "stderr"):
            path_value = receipt.get(f"{stream}_path")
            expected_path = f"shards/{shard['id']}/{stream}.log"
            if path_value != expected_path:
                raise SelectorShardError("receipt log path is not canonical")
            payload = (root / expected_path).read_bytes()
            if len(payload) > _MAX_CAPTURE_BYTES:
                raise SelectorShardError("receipt log exceeds 1 MiB")
            byte_count = receipt.get(f"{stream}_bytes")
            digest = receipt.get(f"{stream}_sha256")
            if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count < 0 or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise SelectorShardError("receipt log metadata types are invalid")
            if len(payload) != byte_count or digest_bytes(payload) != digest:
                raise SelectorShardError("receipt log bytes or digest changed")
            if status != "INVALID_HARNESS":
                try:
                    payload.decode("utf-8", errors="strict")
                except UnicodeDecodeError as error:
                    raise SelectorShardError("receipt log is not UTF-8") from error
        if receipt.get("status") not in _TERMINAL_STATUSES or receipt.get("acceptance_pass") is not False or receipt.get("product_acceptance_pass") is not False or receipt.get("performance_acceptance") is not False or receipt.get("pass_credit") is not False or receipt.get("proxy_acceptance") is not False:
            raise SelectorShardError("receipt status or claims are invalid")
        receipts.append(receipt)
    aggregate = _derive_aggregate_from_receipts(
        normalized,
        receipts,
        aggregate_elapsed_seconds=execution.get("aggregate", {}).get(
            "aggregate_elapsed_seconds", 0
        ),
    )
    if execution.get("aggregate") != aggregate or execution.get("status") != aggregate["status"]:
        raise SelectorShardError("aggregate disagreement")
    for key in ("acceptance_pass", "product_acceptance_pass", "performance_acceptance", "pass_credit", "proxy_acceptance"):
        if execution.get(key) is not False:
            raise SelectorShardError("promoted aggregate claim is forbidden")
    return execution


__all__ = [
    "AGGREGATE_SCHEMA",
    "MANIFEST_SCHEMA",
    "RUNNER_RECEIPT_SCHEMA",
    "SelectorShardError",
    "VALIDATION_SCHEMA",
    "build_selector_shard_manifest",
    "load_selector_shard_manifest",
    "record_selector_aggregate",
    "run_selector_aggregate",
    "run_selector_shard",
    "validate_selector_aggregate_evidence",
    "validate_selector_shard_manifest",
]
