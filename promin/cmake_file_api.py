"""Physical CMake File API admission helpers.

This module never invokes CMake.  It creates the documented query before a
caller configures a build tree and later requires CMake's physical reply files.
The query operation accepts only a typed, current ``SourceSelection`` so a
portable source failure is observed before it creates directories or reserves a
query path.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .canonical import canonical_bytes, digest_value, parse_json_strict
from .input_identity import InputIdentityError, SourceSelection, revalidate_source_selection
from .platform_paths import filesystem_path


class CMakeFileApiError(ValueError):
    """Raised for an unsafe File API path or an incompatible physical reply."""


class CMakeFileApiStatus:
    """Non-crediting File API state labels used by the local helper."""

    PASS = "PASS"
    FAIL = "FAIL"
    UNAVAILABLE = "UNAVAILABLE"


_CLIENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_KIND = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_MAX_REPLY_BYTES = 8 * 1024 * 1024


def _require_client_id(value: object) -> str:
    if not isinstance(value, str) or _CLIENT_ID.fullmatch(value) is None:
        raise CMakeFileApiError("CMake File API client_id is invalid")
    return value


def _is_reparse_or_link(path: Path, inspected: os.stat_result) -> bool:
    if stat.S_ISLNK(inspected.st_mode):
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    attributes = getattr(inspected, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400))


def _lstat_real(path: Path, *, label: str) -> os.stat_result:
    try:
        inspected = os.lstat(filesystem_path(path))
    except OSError as exc:
        raise CMakeFileApiError(f"{label} cannot be inspected: {path}: {exc}") from exc
    if _is_reparse_or_link(path, inspected):
        raise CMakeFileApiError(f"{label} must not be a symbolic link or reparse point: {path}")
    return inspected


def _require_real_directory(path: Path, *, label: str) -> os.stat_result:
    inspected = _lstat_real(path, label=label)
    if not stat.S_ISDIR(inspected.st_mode):
        raise CMakeFileApiError(f"{label} must be a real directory: {path}")
    return inspected


def _require_real_file(path: Path, *, label: str) -> os.stat_result:
    inspected = _lstat_real(path, label=label)
    if not stat.S_ISREG(inspected.st_mode):
        raise CMakeFileApiError(f"{label} must be a regular file: {path}")
    return inspected


def _path_is_absent(path: Path, *, label: str) -> bool:
    try:
        os.lstat(filesystem_path(path))
    except FileNotFoundError:
        return True
    except OSError as exc:
        raise CMakeFileApiError(f"{label} cannot be inspected: {path}: {exc}") from exc
    return False


def _read_bytes(path: Path, *, label: str) -> bytes:
    try:
        with open(filesystem_path(path), "rb") as stream:
            return stream.read()
    except OSError as exc:
        raise CMakeFileApiError(f"{label} cannot be read: {path}: {exc}") from exc


def _digest_path(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with open(filesystem_path(path), "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise CMakeFileApiError(f"CMake File API file cannot be read: {path}: {exc}") from exc
    return digest.hexdigest()


def _load_reply_json(path: Path) -> Mapping[str, Any]:
    _require_real_file(path, label="CMake File API reply")
    raw = _read_bytes(path, label="CMake File API reply")
    if len(raw) > _MAX_REPLY_BYTES:
        raise CMakeFileApiError("CMake File API reply exceeds the bounded parser input")
    try:
        value = parse_json_strict(raw)
    except Exception as exc:
        raise CMakeFileApiError(f"CMake File API reply is not strict JSON: {path}") from exc
    if not isinstance(value, Mapping):
        raise CMakeFileApiError(f"CMake File API reply root must be an object: {path}")
    return value


def _reply_file_name(value: object) -> str:
    if not isinstance(value, str) or not value or "/" in value or "\\" in value:
        raise CMakeFileApiError("CMake File API response jsonFile must be one local filename")
    if value in {".", ".."} or "\x00" in value:
        raise CMakeFileApiError("CMake File API response jsonFile is invalid")
    return value


@dataclass(frozen=True)
class CMakeFileApiRequest:
    """One exact CMake object request with a minimum accepted major version."""

    kind: str
    major: int

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or _KIND.fullmatch(self.kind) is None:
            raise CMakeFileApiError("CMake File API request kind is invalid")
        if not isinstance(self.major, int) or isinstance(self.major, bool) or self.major < 1:
            raise CMakeFileApiError("CMake File API request major version is invalid")

    def to_query_record(self) -> dict[str, Any]:
        return {"kind": self.kind, "version": [{"major": self.major}]}


DEFAULT_REQUESTS = (
    CMakeFileApiRequest("codemodel", 2),
    CMakeFileApiRequest("toolchains", 1),
)


def _canonical_requests(values: Iterable[CMakeFileApiRequest]) -> tuple[CMakeFileApiRequest, ...]:
    requests = tuple(values)
    if not requests or any(not isinstance(item, CMakeFileApiRequest) for item in requests):
        raise CMakeFileApiError("CMake File API requests must be non-empty typed requests")
    ordered = tuple(sorted(requests, key=lambda item: (item.kind.encode("utf-8"), item.major)))
    kinds = [item.kind for item in ordered]
    if len(set(kinds)) != len(kinds):
        raise CMakeFileApiError("CMake File API requests duplicate an object kind")
    return ordered


@dataclass(frozen=True)
class CMakeFileApiQuery:
    """A create-only physical query tied to one source-selection identity."""

    build_root: Path
    client_id: str
    requests: tuple[CMakeFileApiRequest, ...]
    source_selection: SourceSelection
    query_sha256: str
    created: bool

    def __post_init__(self) -> None:
        if not isinstance(self.build_root, Path):
            raise CMakeFileApiError("CMake build_root must be a Path")
        object.__setattr__(self, "client_id", _require_client_id(self.client_id))
        object.__setattr__(self, "requests", _canonical_requests(self.requests))
        if not isinstance(self.source_selection, SourceSelection):
            raise CMakeFileApiError("CMake File API query requires a typed source selection")
        if not isinstance(self.query_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", self.query_sha256):
            raise CMakeFileApiError("CMake File API query digest is invalid")
        if not isinstance(self.created, bool):
            raise CMakeFileApiError("CMake File API query created flag is invalid")

    @property
    def query_path(self) -> Path:
        return (
            self.build_root
            / ".cmake"
            / "api"
            / "v1"
            / "query"
            / f"client-{self.client_id}"
            / "query.json"
        )

    @property
    def reply_root(self) -> Path:
        return self.build_root / ".cmake" / "api" / "v1" / "reply"

    @property
    def query_record(self) -> dict[str, Any]:
        return {"requests": [item.to_query_record() for item in self.requests]}

    def to_record(self) -> dict[str, Any]:
        identity = {
            "record_type": "CMakeFileApiQuery",
            "schema": "promin.cmake-file-api-query.v1",
            "client_id": self.client_id,
            "requests": [item.to_query_record() for item in self.requests],
            "source_selection_digest": self.source_selection.selection_digest,
            "query_sha256": self.query_sha256,
            "created": self.created,
        }
        return {
            **identity,
            "query_digest": digest_value(identity),
            "acceptance_pass": False,
            "pass_credit": False,
        }


def _ensure_query_parent(build_root: Path, client_id: str) -> Path:
    """Create a query directory only after source preflight has succeeded."""

    build_root = build_root.absolute()
    try:
        build_root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CMakeFileApiError(f"CMake build root cannot be created: {build_root}: {exc}") from exc
    _require_real_directory(build_root, label="CMake build root")
    current = build_root
    for component in (".cmake", "api", "v1", "query", f"client-{client_id}"):
        current = current / component
        try:
            current.mkdir(exist_ok=True)
        except OSError as exc:
            raise CMakeFileApiError(f"CMake File API query directory cannot be created: {current}: {exc}") from exc
        _require_real_directory(current, label="CMake File API query directory")
    return current


def create_cmake_file_api_query(
    build_root: str | os.PathLike[str],
    source_selection: SourceSelection,
    *,
    client_id: str = "promin",
    requests: Iterable[CMakeFileApiRequest] = DEFAULT_REQUESTS,
) -> CMakeFileApiQuery:
    """Create or exact-reuse a CMake query after portable source validation.

    A different existing query is never replaced.  The source selection is
    re-read immediately after a create-only file reservation; on drift, the
    file created by this invocation is removed and no query is returned.
    """

    if not isinstance(source_selection, SourceSelection):
        raise CMakeFileApiError("source selection must be typed before CMake query creation")
    client = _require_client_id(client_id)
    selected_requests = _canonical_requests(requests)
    # This must stay before every mkdir/open call in this function.
    try:
        revalidate_source_selection(source_selection)
    except InputIdentityError as exc:
        raise CMakeFileApiError(f"source selection failed before CMake mutation: {exc}") from exc
    query_record = {"requests": [item.to_query_record() for item in selected_requests]}
    query_bytes = canonical_bytes(query_record) + b"\n"
    query_sha256 = hashlib.sha256(query_bytes).hexdigest()
    parent = _ensure_query_parent(Path(build_root), client)
    query_path = parent / "query.json"
    created = False
    existing = (
        None
        if _path_is_absent(query_path, label="CMake File API query")
        else _require_real_file(query_path, label="existing CMake File API query")
    )
    if existing is not None:
        actual = _read_bytes(query_path, label="existing CMake File API query")
        if actual != query_bytes:
            raise CMakeFileApiError("existing CMake File API query differs; replacement is forbidden")
    else:
        try:
            with open(filesystem_path(query_path), "xb") as stream:
                stream.write(query_bytes)
                stream.flush()
                os.fsync(stream.fileno())
            created = True
        except FileExistsError:
            # A competing writer won a create-only race.  It is safe only if it
            # wrote exactly the same query; recurse through the exact-reuse path.
            return create_cmake_file_api_query(
                build_root,
                source_selection,
                client_id=client,
                requests=selected_requests,
            )
        except OSError as exc:
            raise CMakeFileApiError(f"CMake File API query cannot be reserved: {query_path}: {exc}") from exc
    try:
        revalidate_source_selection(source_selection)
    except InputIdentityError as exc:
        if created:
            try:
                query_path.unlink()
            except OSError:
                # The caller still receives the source failure.  A later
                # lifecycle/cleanup operation must not treat this as a valid query.
                pass
        raise CMakeFileApiError(f"source selection changed after CMake reservation: {exc}") from exc
    return CMakeFileApiQuery(
        build_root=Path(build_root).absolute(),
        client_id=client,
        requests=selected_requests,
        source_selection=source_selection,
        query_sha256=query_sha256,
        created=created,
    )


def _matching_reply_request(
    replies: object, request: CMakeFileApiRequest
) -> Mapping[str, Any] | None:
    if not isinstance(replies, list):
        return None
    matches: list[Mapping[str, Any]] = []
    for item in replies:
        if not isinstance(item, Mapping) or item.get("kind") != request.kind:
            continue
        version = item.get("version")
        major = version.get("major") if isinstance(version, Mapping) else None
        if major == request.major:
            matches.append(item)
    if len(matches) != 1:
        return None
    return matches[0]


@dataclass(frozen=True)
class CMakeFileApiReply:
    """The physical reply evidence for a query; never a product acceptance."""

    query: CMakeFileApiQuery
    status: str
    index_sha256: str | None
    response_files: tuple[tuple[str, str], ...]
    errors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.query, CMakeFileApiQuery):
            raise CMakeFileApiError("CMake File API reply must reference a typed query")
        if self.status not in {CMakeFileApiStatus.PASS, CMakeFileApiStatus.FAIL, CMakeFileApiStatus.UNAVAILABLE}:
            raise CMakeFileApiError("CMake File API reply status is invalid")
        if self.index_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", self.index_sha256):
            raise CMakeFileApiError("CMake File API index digest is invalid")

    def to_record(self) -> dict[str, Any]:
        identity = {
            "record_type": "CMakeFileApiReply",
            "schema": "promin.cmake-file-api-reply.v1",
            "query_digest": self.query.to_record()["query_digest"],
            "status": self.status,
            "index_sha256": self.index_sha256,
            "response_files": [
                {"path": path, "sha256": digest} for path, digest in self.response_files
            ],
            "errors": list(self.errors),
        }
        return {
            **identity,
            "reply_digest": digest_value(identity),
            "acceptance_pass": False,
            "pass_credit": False,
        }


def _latest_index(reply_root: Path) -> Path | None:
    try:
        entries = [
            Path(entry.path)
            for entry in os.scandir(filesystem_path(reply_root))
            if entry.name.startswith("index-") and entry.name.endswith(".json")
        ]
    except OSError as exc:
        raise CMakeFileApiError(f"CMake File API reply directory cannot be enumerated: {reply_root}: {exc}") from exc
    if not entries:
        return None
    inspected: list[tuple[int, bytes, Path]] = []
    for entry in entries:
        stats = _require_real_file(entry, label="CMake File API index")
        inspected.append((stats.st_mtime_ns, entry.name.encode("utf-8"), entry))
    return max(inspected)[2]


def read_cmake_file_api_reply(query: CMakeFileApiQuery) -> CMakeFileApiReply:
    """Require CMake's real reply index and every requested response file."""

    if not isinstance(query, CMakeFileApiQuery):
        raise CMakeFileApiError("CMake File API reply requires a typed query")
    try:
        revalidate_source_selection(query.source_selection)
    except InputIdentityError as exc:
        raise CMakeFileApiError(f"source selection changed before CMake reply read: {exc}") from exc
    try:
        _require_real_file(query.query_path, label="CMake File API query")
        if _digest_path(query.query_path) != query.query_sha256:
            raise CMakeFileApiError("CMake File API query bytes no longer match its identity")
    except CMakeFileApiError:
        raise
    if _path_is_absent(query.reply_root, label="CMake File API reply directory"):
        return CMakeFileApiReply(query, CMakeFileApiStatus.UNAVAILABLE, None, (), ("CMake reply directory is absent",))
    _require_real_directory(query.reply_root, label="CMake File API reply directory")
    index = _latest_index(query.reply_root)
    if index is None:
        return CMakeFileApiReply(query, CMakeFileApiStatus.UNAVAILABLE, None, (), ("CMake reply index is absent",))
    try:
        index_value = _load_reply_json(index)
    except CMakeFileApiError as exc:
        return CMakeFileApiReply(query, CMakeFileApiStatus.FAIL, _digest_path(index), (), (str(exc),))
    reply = index_value.get("reply")
    client = reply.get(f"client-{query.client_id}") if isinstance(reply, Mapping) else None
    query_reply = client.get("query.json") if isinstance(client, Mapping) else None
    requests = query_reply.get("requests") if isinstance(query_reply, Mapping) else None
    if not isinstance(requests, list):
        return CMakeFileApiReply(
            query,
            CMakeFileApiStatus.UNAVAILABLE,
            _digest_path(index),
            (),
            ("CMake reply does not contain this client query",),
        )
    response_files: list[tuple[str, str]] = []
    errors: list[str] = []
    for request in query.requests:
        matched = _matching_reply_request(requests, request)
        if matched is None:
            errors.append(f"CMake reply lacks exact {request.kind} v{request.major} response")
            continue
        if "error" in matched:
            errors.append(f"CMake reply rejected {request.kind} v{request.major}")
            continue
        try:
            filename = _reply_file_name(matched.get("jsonFile"))
            response_path = query.reply_root / filename
            _load_reply_json(response_path)
            response_files.append((filename, _digest_path(response_path)))
        except CMakeFileApiError as exc:
            errors.append(str(exc))
    status = CMakeFileApiStatus.PASS if not errors else CMakeFileApiStatus.FAIL
    return CMakeFileApiReply(
        query,
        status,
        _digest_path(index),
        tuple(sorted(response_files, key=lambda item: item[0].encode("utf-8"))),
        tuple(errors),
    )


def require_cmake_file_api_reply(query: CMakeFileApiQuery) -> CMakeFileApiReply:
    """Return a physical reply only when every requested CMake object exists."""

    reply = read_cmake_file_api_reply(query)
    if reply.status != CMakeFileApiStatus.PASS:
        raise CMakeFileApiError("CMake File API physical reply is not available: " + "; ".join(reply.errors))
    return reply
