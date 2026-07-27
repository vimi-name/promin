from __future__ import annotations

import datetime as _datetime
import hashlib
import json
import math
import os
import re
import stat
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


class CanonicalError(ValueError):
    """Raised when input cannot participate in Promin canonical identity."""


_UTC_SECOND = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)


def format_utc_second(value: _datetime.datetime) -> str:
    """Format one exact real-calendar UTC instant at whole-second resolution."""

    if (
        not isinstance(value, _datetime.datetime)
        or value.tzinfo is None
        or value.utcoffset() != _datetime.timedelta(0)
        or value.microsecond != 0
        or not 1 <= value.year <= 9999
    ):
        raise CanonicalError(
            "timestamp must be a timezone-aware UTC datetime at whole-second resolution"
        )
    normalized = value.astimezone(_datetime.timezone.utc)
    return (
        f"{normalized.year:04d}-{normalized.month:02d}-{normalized.day:02d}T"
        f"{normalized.hour:02d}:{normalized.minute:02d}:{normalized.second:02d}Z"
    )


def parse_utc_second(value: str) -> _datetime.datetime:
    """Parse canonical ``YYYY-MM-DDTHH:MM:SSZ`` using the real UTC calendar."""

    if not isinstance(value, str) or _UTC_SECOND.fullmatch(value) is None:
        raise CanonicalError("timestamp must use exact YYYY-MM-DDTHH:MM:SSZ form")
    try:
        parsed = _datetime.datetime(
            int(value[0:4]),
            int(value[5:7]),
            int(value[8:10]),
            int(value[11:13]),
            int(value[14:16]),
            int(value[17:19]),
            tzinfo=_datetime.timezone.utc,
        )
    except ValueError as exc:
        raise CanonicalError("timestamp is not a real UTC calendar second") from exc
    if format_utc_second(parsed) != value:
        raise CanonicalError("timestamp does not round-trip canonically")
    return parsed


@dataclass(frozen=True)
class ParseLimits:
    max_bytes: int = 16 * 1024 * 1024
    max_depth: int = 64
    max_items: int = 1_000_000
    max_string_length: int = 1_048_576
    max_number_length: int = 256

    def __post_init__(self) -> None:
        for field_name, value in vars(self).items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{field_name} must be a positive integer")


DEFAULT_LIMITS = ParseLimits()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _is_link_or_reparse(
    path: Path,
    inspected: os.stat_result | None = None,
) -> bool:
    value = inspected if inspected is not None else path.lstat()
    if stat.S_ISLNK(value.st_mode) or path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    attributes = getattr(value, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
    return bool(attributes & reparse_flag)


def _reject_link_components(path: Path, root: Path | None) -> None:
    boundary = (root if root is not None else path.parent).resolve(strict=True)
    if root is not None and (_is_link_or_reparse(root) or not root.is_dir()):
        raise CanonicalError(f"path root must be a real directory: {root}")
    try:
        relative = path.absolute().relative_to(boundary.absolute())
    except ValueError as exc:
        raise CanonicalError(f"path escapes configured root: {path}") from exc
    cursor = boundary
    for part in relative.parts:
        cursor = cursor / part
        try:
            mode = cursor.lstat().st_mode
        except OSError as exc:
            raise CanonicalError(f"path cannot be inspected: {cursor}: {exc}") from exc
        if _is_link_or_reparse(cursor):
            raise CanonicalError(f"symbolic link or reparse point rejected: {cursor}")


def require_regular_file(path: str | os.PathLike[str], *, root: str | os.PathLike[str] | None = None) -> Path:
    candidate = Path(path)
    if root is not None and not candidate.is_absolute():
        root_absolute = Path(root).absolute()
        candidate_absolute = candidate.absolute()
        candidate = (
            candidate_absolute
            if _is_relative_to(candidate_absolute, root_absolute)
            else Path(root) / candidate
        )
    configured_root = None
    if root is not None:
        root_path = Path(root)
        try:
            root_stat = root_path.lstat()
        except OSError as exc:
            raise CanonicalError(f"path root cannot be inspected: {root_path}: {exc}") from exc
        if _is_link_or_reparse(root_path, root_stat) or not stat.S_ISDIR(root_stat.st_mode):
            raise CanonicalError(f"path root must be a real directory: {root_path}")
        configured_root = root_path.resolve(strict=True)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise CanonicalError(f"required file is unavailable: {candidate}: {exc}") from exc
    if configured_root is not None and not _is_relative_to(resolved, configured_root):
        raise CanonicalError(f"path escapes configured root: {candidate}")
    _reject_link_components(candidate, configured_root)
    try:
        mode = candidate.stat(follow_symlinks=False).st_mode
    except OSError as exc:
        raise CanonicalError(f"file cannot be inspected: {candidate}: {exc}") from exc
    if not stat.S_ISREG(mode):
        raise CanonicalError(f"expected regular file: {candidate}")
    return resolved


def ensure_exact_regular_files(
    directory: str | os.PathLike[str], expected: Iterable[str]
) -> tuple[Path, ...]:
    base = Path(directory)
    try:
        mode = base.stat(follow_symlinks=False).st_mode
    except OSError as exc:
        raise CanonicalError(f"directory cannot be inspected: {base}: {exc}") from exc
    if _is_link_or_reparse(base) or not stat.S_ISDIR(mode):
        raise CanonicalError(f"expected real directory: {base}")
    expected_names = tuple(expected)
    if len(expected_names) != len(set(expected_names)):
        raise CanonicalError("expected file set contains duplicates")
    entries = tuple(base.iterdir())
    actual_names = {entry.name for entry in entries}
    if actual_names != set(expected_names) or len(entries) != len(expected_names):
        raise CanonicalError(
            f"exact file-set mismatch at {base}: "
            f"expected={sorted(expected_names)} actual={sorted(actual_names)}"
        )
    by_name = {entry.name: require_regular_file(entry, root=base) for entry in entries}
    return tuple(by_name[name] for name in expected_names)


def _normalize(value: Any, limits: ParseLimits, *, depth: int, counter: list[int]) -> Any:
    if depth > limits.max_depth:
        raise CanonicalError(f"JSON nesting exceeds {limits.max_depth}")
    counter[0] += 1
    if counter[0] > limits.max_items:
        raise CanonicalError(f"JSON item count exceeds {limits.max_items}")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if len(str(abs(value))) > limits.max_number_length:
            raise CanonicalError("JSON integer exceeds numeric length limit")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalError("non-finite JSON number rejected")
        return value
    if isinstance(value, str):
        normalized = unicodedata.normalize("NFC", value)
        if len(normalized) > limits.max_string_length:
            raise CanonicalError(f"JSON string exceeds {limits.max_string_length} characters")
        return normalized
    if isinstance(value, list):
        return [_normalize(item, limits, depth=depth + 1, counter=counter) for item in value]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError("JSON object key must be a string")
            normalized_key = unicodedata.normalize("NFC", key)
            if len(normalized_key) > limits.max_string_length:
                raise CanonicalError("JSON object key exceeds string length limit")
            if normalized_key in result:
                raise CanonicalError(f"JSON key collision after NFC: {normalized_key!r}")
            result[normalized_key] = _normalize(
                item, limits, depth=depth + 1, counter=counter
            )
        return result
    raise CanonicalError(f"unsupported canonical JSON type: {type(value).__name__}")


def normalize_json(value: Any, *, limits: ParseLimits = DEFAULT_LIMITS) -> Any:
    return _normalize(value, limits, depth=1, counter=[0])


def _pairs_without_collision(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    raw_keys: set[str] = set()
    normalized_keys: dict[str, str] = {}
    for key, value in pairs:
        if key in raw_keys:
            raise CanonicalError(f"duplicate JSON key: {key!r}")
        raw_keys.add(key)
        normalized = unicodedata.normalize("NFC", key)
        previous = normalized_keys.get(normalized)
        if previous is not None:
            raise CanonicalError(
                f"JSON key collision after NFC: {previous!r} vs {key!r}"
            )
        normalized_keys[normalized] = key
        result[key] = value
    return result


def _bounded_integer(text: str, limits: ParseLimits) -> int:
    if len(text.lstrip("-")) > limits.max_number_length:
        raise CanonicalError("JSON integer exceeds numeric length limit")
    return int(text)


def _bounded_float(text: str, limits: ParseLimits) -> float:
    if len(text) > limits.max_number_length:
        raise CanonicalError("JSON number exceeds numeric length limit")
    value = float(text)
    if not math.isfinite(value):
        raise CanonicalError("non-finite JSON number rejected")
    return value


def parse_json_strict(data: bytes, *, limits: ParseLimits = DEFAULT_LIMITS) -> Any:
    if len(data) > limits.max_bytes:
        raise CanonicalError(f"JSON input exceeds {limits.max_bytes} bytes")
    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_pairs_without_collision,
            parse_int=lambda raw: _bounded_integer(raw, limits),
            parse_float=lambda raw: _bounded_float(raw, limits),
            parse_constant=lambda raw: (_ for _ in ()).throw(
                CanonicalError(f"non-finite JSON number rejected: {raw}")
            ),
        )
    except CanonicalError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise CanonicalError(f"invalid bounded UTF-8 JSON: {exc}") from exc
    return normalize_json(value, limits=limits)


def load_json_strict(
    path: str | os.PathLike[str],
    *,
    root: str | os.PathLike[str] | None = None,
    limits: ParseLimits = DEFAULT_LIMITS,
) -> Any:
    resolved = require_regular_file(path, root=root)
    try:
        with resolved.open("rb") as handle:
            data = handle.read(limits.max_bytes + 1)
    except OSError as exc:
        raise CanonicalError(f"cannot read JSON file {resolved}: {exc}") from exc
    return parse_json_strict(data, limits=limits)


def canonical_bytes(value: Any, *, limits: ParseLimits = DEFAULT_LIMITS) -> bytes:
    normalized = normalize_json(value, limits=limits)
    try:
        encoded = json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError) as exc:
        raise CanonicalError(f"value is not canonical JSON: {exc}") from exc
    if len(encoded) > limits.max_bytes:
        raise CanonicalError(f"canonical JSON exceeds {limits.max_bytes} bytes")
    return encoded


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_value(value: Any, *, limits: ParseLimits = DEFAULT_LIMITS) -> str:
    return digest_bytes(canonical_bytes(value, limits=limits))


def digest_file(
    path: str | os.PathLike[str], *, root: str | os.PathLike[str] | None = None
) -> str:
    resolved = require_regular_file(path, root=root)
    result = hashlib.sha256()
    try:
        with resolved.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                result.update(chunk)
    except OSError as exc:
        raise CanonicalError(f"cannot digest file {resolved}: {exc}") from exc
    return result.hexdigest()


def fsync_directory(directory: str | os.PathLike[str]) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(Path(directory), flags)
    except OSError:
        if os.name == "nt":
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_bytes(path: str | os.PathLike[str], data: bytes, *, mode: int = 0o600) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".p-", suffix=".tmp", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, target)
        fsync_directory(target.parent)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        finally:
            raise


def atomic_write_json(
    path: str | os.PathLike[str],
    value: Any,
    *,
    limits: ParseLimits = DEFAULT_LIMITS,
    mode: int = 0o600,
) -> None:
    atomic_write_bytes(path, canonical_bytes(value, limits=limits), mode=mode)
