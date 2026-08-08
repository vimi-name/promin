"""External, deterministic final-package admission for a tracked source tree.

Admission receives an explicit tracked-file boundary.  It may read that source
tree, but all clones, archives, and receipts are written below a separate
external output directory.  The result is a candidate evidence record, never
an acceptance or deployment decision.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import tempfile
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .canonical import canonical_bytes, digest_bytes
from .platform_paths import PlatformPathError, filesystem_path, resolve_contained_path


FINAL_ADMISSION_SCHEMA = "promin.final-package-admission.v1"
MAX_ADMISSION_FILES = 4_096
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_DELETE_ITEMS = 16_384
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
CANONICAL_ARCHIVE_MODES = frozenset({0o644, 0o755})

_PATH_COMPONENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
_DOT_PATH_COMPONENT = re.compile(r"^\.[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_RESERVED = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CLOCK$",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
    }
)
_EXCLUDED_COMPONENT_REASONS = {
    ".git": "repository-metadata",
    ".promin": "operational-state",
    ".promin-host": "host-operational-state",
    ".pytest_cache": "test-cache",
    ".mypy_cache": "analysis-cache",
    ".cache": "cache",
    "__pycache__": "python-bytecode-cache",
    ".venv": "local-environment",
    "venv": "local-environment",
    "build": "build-output",
    "dist": "build-output",
    "htmlcov": "coverage-output",
    "coverage": "coverage-output",
    "_work": "local-workspace",
}
_EXCLUDED_FILE_SUFFIXES = {
    ".pyc": "python-bytecode",
    ".pyo": "python-bytecode",
    ".sqlite": "operational-database",
    ".sqlite3": "operational-database",
    ".db": "operational-database",
}


class FinalAdmissionError(ValueError):
    """Raised when a candidate boundary cannot be deterministically admitted."""


@dataclass(frozen=True, slots=True)
class _Node:
    path: str
    kind: str
    native_path: Path
    stat_result: os.stat_result


def _sort_key(value: str) -> bytes:
    return value.encode("utf-8")


def _is_link_or_reparse(path: Path, inspected: os.stat_result) -> bool:
    if stat.S_ISLNK(inspected.st_mode) or os.path.islink(filesystem_path(path)):
        return True
    attributes = getattr(inspected, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
    return bool(attributes & reparse_flag)


def _lstat(path: Path, label: str) -> os.stat_result:
    try:
        return os.lstat(filesystem_path(path))
    except OSError as exc:
        raise FinalAdmissionError(f"{label} cannot be inspected: {path}") from exc


def _require_real_directory(path: str | os.PathLike[str], label: str) -> Path:
    candidate = Path(path)
    inspected = _lstat(candidate, label)
    if _is_link_or_reparse(candidate, inspected) or not stat.S_ISDIR(inspected.st_mode):
        raise FinalAdmissionError(f"{label} must be a real directory")
    try:
        resolved = resolve_contained_path(candidate, root=candidate.parent)
    except PlatformPathError as exc:
        raise FinalAdmissionError(f"{label} cannot be resolved safely") from exc
    resolved_inspected = _lstat(resolved, label)
    if _is_link_or_reparse(resolved, resolved_inspected) or not stat.S_ISDIR(
        resolved_inspected.st_mode
    ):
        raise FinalAdmissionError(f"{label} must resolve to a real directory")
    return resolved


def _relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512:
        raise FinalAdmissionError(f"{label} must be a bounded non-empty UTF-8 path")
    if unicodedata.normalize("NFC", value) != value:
        raise FinalAdmissionError(f"{label} must be NFC")
    if "\\" in value or "\x00" in value or value.startswith("/") or value.endswith("/"):
        raise FinalAdmissionError(f"{label} must be a normalized relative POSIX path")
    components = value.split("/")
    if len(components) > 24 or any(
        not component or component in {".", ".."} for component in components
    ):
        raise FinalAdmissionError(f"{label} has invalid path components")
    for component in components:
        if ":" in component or component.endswith((".", " ")):
            raise FinalAdmissionError(f"{label} is not portable to Windows")
        if _PATH_COMPONENT.fullmatch(component) is None and _DOT_PATH_COMPONENT.fullmatch(component) is None:
            raise FinalAdmissionError(f"{label} has unsupported path characters")
        if component.lstrip(".").split(".", 1)[0].upper() in _WINDOWS_RESERVED:
            raise FinalAdmissionError(f"{label} uses a Windows reserved name")
    return value


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _source_is_ancestor_of(candidate: Path, source_root: Path) -> bool:
    try:
        common = os.path.commonpath((str(candidate.absolute()), str(source_root.absolute())))
    except ValueError as exc:
        raise FinalAdmissionError("source and output roots use incompatible anchors") from exc
    return os.path.normcase(common) == os.path.normcase(str(source_root))


def _walk_real_tree(root: Path) -> tuple[_Node, ...]:
    """Read every node without following links or reparse points."""

    nodes: list[_Node] = []

    def visit(directory: Path, relative: str) -> None:
        try:
            entries = list(os.scandir(filesystem_path(directory)))
        except OSError as exc:
            raise FinalAdmissionError(f"source tree cannot be enumerated: {relative or '.'}") from exc
        entries.sort(key=lambda entry: _sort_key(entry.name))
        for entry in entries:
            path = directory / entry.name
            try:
                inspected = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise FinalAdmissionError(f"source node cannot be inspected: {entry.name}") from exc
            item_relative = entry.name if not relative else f"{relative}/{entry.name}"
            _relative_path(item_relative, "source tree path")
            if _is_link_or_reparse(path, inspected):
                raise FinalAdmissionError(
                    f"source tree contains a symbolic link or reparse point: {item_relative}"
                )
            if stat.S_ISDIR(inspected.st_mode):
                nodes.append(_Node(item_relative, "directory", path, inspected))
                visit(path, item_relative)
            elif stat.S_ISREG(inspected.st_mode):
                nodes.append(_Node(item_relative, "file", path, inspected))
            else:
                raise FinalAdmissionError(
                    f"source tree contains a non-regular special entry: {item_relative}"
                )

    visit(root, "")
    return tuple(nodes)


def _excluded_reason(path: str, kind: str) -> str | None:
    for component in path.split("/"):
        reason = _EXCLUDED_COMPONENT_REASONS.get(component)
        if reason is not None:
            return reason
    if kind == "file":
        lowered = path.casefold()
        for suffix, reason in _EXCLUDED_FILE_SUFFIXES.items():
            if lowered.endswith(suffix):
                return reason
    return None


def _canonical_archive_mode(inspected: os.stat_result) -> int:
    return 0o755 if stat.S_IMODE(inspected.st_mode) & 0o111 else 0o644


def _digest_file(path: Path, expected_size: int) -> str:
    if expected_size > MAX_FILE_BYTES:
        raise FinalAdmissionError(f"admission file exceeds {MAX_FILE_BYTES} bytes: {path.name}")
    try:
        before = os.stat(filesystem_path(path), follow_symlinks=False)
    except OSError as exc:
        raise FinalAdmissionError(f"admission file cannot be measured: {path}") from exc
    digest = hashlib.sha256()
    observed = 0
    try:
        with open(filesystem_path(path), "rb") as handle:
            while True:
                chunk = handle.read(128 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                observed += len(chunk)
    except OSError as exc:
        raise FinalAdmissionError(f"admission file cannot be read: {path}") from exc
    try:
        after = os.stat(filesystem_path(path), follow_symlinks=False)
    except OSError as exc:
        raise FinalAdmissionError(f"admission file disappeared while being read: {path}") from exc
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or observed != expected_size:
        raise FinalAdmissionError(f"admission file changed while being read: {path}")
    return digest.hexdigest()


def _validated_tracked_paths(tracked_paths: Iterable[str]) -> tuple[str, ...]:
    values = tuple(_relative_path(path, "tracked_paths entry") for path in tracked_paths)
    if not values or len(values) > MAX_ADMISSION_FILES:
        raise FinalAdmissionError("tracked_paths must be a bounded non-empty sequence")
    if tuple(sorted(values, key=_sort_key)) != values:
        raise FinalAdmissionError("tracked_paths must use canonical UTF-8 sort order")
    if len({value.casefold() for value in values}) != len(values):
        raise FinalAdmissionError("tracked_paths contains duplicate portable paths")
    for value in values:
        if _excluded_reason(value, "file") is not None:
            raise FinalAdmissionError("tracked_paths may not include operational or generated paths")
    return values


def _source_boundary(
    source_root: Path,
    tracked_paths: tuple[str, ...],
) -> tuple[list[dict[str, Any]], list[dict[str, str]], tuple[tuple[Any, ...], ...]]:
    nodes = _walk_real_tree(source_root)
    tracked_set = set(tracked_paths)
    files: list[dict[str, Any]] = []
    deletes: list[dict[str, str]] = []
    normal_directories: list[str] = []
    observed_tracked: set[str] = set()
    total_bytes = 0
    signature: list[tuple[Any, ...]] = []
    root_stat = _lstat(source_root, "source root")
    signature.append(("", "directory", root_stat.st_dev, root_stat.st_ino, root_stat.st_size, root_stat.st_mtime_ns))
    for node in nodes:
        signature.append(
            (
                node.path,
                node.kind,
                node.stat_result.st_dev,
                node.stat_result.st_ino,
                node.stat_result.st_size,
                node.stat_result.st_mtime_ns,
            )
        )
        reason = _excluded_reason(node.path, node.kind)
        if reason is not None:
            if node.kind == "file" and node.path in tracked_set:
                raise FinalAdmissionError(
                    f"tracked path is forbidden operational/generated state: {node.path}"
                )
            deletes.append({"path": node.path, "kind": node.kind, "reason": reason})
            continue
        if node.kind == "directory":
            normal_directories.append(node.path)
            continue
        if node.path not in tracked_set:
            raise FinalAdmissionError(f"source file is outside the declared tracked boundary: {node.path}")
        if node.path in observed_tracked:
            raise FinalAdmissionError(f"source tree repeated tracked path: {node.path}")
        observed_tracked.add(node.path)
        if node.stat_result.st_size > MAX_FILE_BYTES:
            raise FinalAdmissionError(f"admission file exceeds {MAX_FILE_BYTES} bytes: {node.path}")
        digest = _digest_file(node.native_path, node.stat_result.st_size)
        total_bytes += node.stat_result.st_size
        if total_bytes > MAX_TOTAL_BYTES:
            raise FinalAdmissionError(f"admission files exceed {MAX_TOTAL_BYTES} bytes")
        files.append(
            {
                "path": node.path,
                "bytes": node.stat_result.st_size,
                "sha256": digest,
                "mode": _canonical_archive_mode(node.stat_result),
            }
        )
    if observed_tracked != tracked_set:
        missing = sorted(tracked_set - observed_tracked, key=_sort_key)
        raise FinalAdmissionError(f"tracked boundary is missing source files: {missing}")
    for directory in normal_directories:
        if not any(_under(path, directory) for path in tracked_paths):
            raise FinalAdmissionError(
                f"source directory is outside the declared tracked boundary: {directory}"
            )
    files.sort(key=lambda item: _sort_key(item["path"]))
    deletes.sort(key=lambda item: (_sort_key(item["path"]), _sort_key(item["kind"])))
    if len(deletes) > MAX_DELETE_ITEMS:
        raise FinalAdmissionError(f"delete manifest exceeds {MAX_DELETE_ITEMS} entries")
    return files, deletes, tuple(signature)


def _tree_digest(files: Sequence[Mapping[str, Any]]) -> str:
    rows = [
        {
            "path": item["path"],
            "bytes": item["bytes"],
            "sha256": item["sha256"],
            "mode": item["mode"],
        }
        for item in files
    ]
    return digest_bytes(canonical_bytes(rows))


def _copy_clone(source_root: Path, clone_root: Path, files: Sequence[Mapping[str, Any]]) -> None:
    clone_root.mkdir(mode=0o700)
    for item in files:
        source = source_root / str(item["path"])
        target = clone_root / str(item["path"])
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            with open(filesystem_path(source), "rb") as reader, open(
                filesystem_path(target), "xb"
            ) as writer:
                while True:
                    chunk = reader.read(128 * 1024)
                    if not chunk:
                        break
                    writer.write(chunk)
            os.chmod(filesystem_path(target), int(item["mode"]))
        except OSError as exc:
            raise FinalAdmissionError(f"clone cannot materialize {item['path']}") from exc


def _verify_clone(clone_root: Path, files: Sequence[Mapping[str, Any]]) -> str:
    nodes = _walk_real_tree(clone_root)
    cloned_files = [node for node in nodes if node.kind == "file"]
    expected = [str(item["path"]) for item in files]
    if [node.path for node in cloned_files] != expected:
        raise FinalAdmissionError("independent clone file set differs from the tracked boundary")
    for node, expected_item in zip(cloned_files, files, strict=True):
        if node.stat_result.st_size != expected_item["bytes"]:
            raise FinalAdmissionError(f"independent clone byte count differs: {node.path}")
        if _digest_file(node.native_path, node.stat_result.st_size) != expected_item["sha256"]:
            raise FinalAdmissionError(f"independent clone digest differs: {node.path}")
        if _canonical_archive_mode(node.stat_result) != expected_item["mode"]:
            raise FinalAdmissionError(f"independent clone mode differs: {node.path}")
    return _tree_digest(files)


def _archive_prefix(value: str) -> str:
    return _relative_path(value, "archive_prefix")


def _archive_name(value: str) -> str:
    if not isinstance(value, str) or not value.endswith(".zip"):
        raise FinalAdmissionError("archive_name must end in .zip")
    name = _relative_path(value, "archive_name")
    if "/" in name:
        raise FinalAdmissionError("archive_name must be one filename")
    return name


def _write_archive(
    clone_root: Path,
    archive_path: Path,
    files: Sequence[Mapping[str, Any]],
    archive_prefix: str,
) -> None:
    try:
        with zipfile.ZipFile(
            filesystem_path(archive_path),
            mode="x",
            compression=zipfile.ZIP_STORED,
            strict_timestamps=True,
        ) as archive:
            archive.comment = b""
            for item in files:
                entry_name = f"{archive_prefix}/{item['path']}"
                info = zipfile.ZipInfo(entry_name, date_time=FIXED_ZIP_TIMESTAMP)
                info.create_system = 3
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = (stat.S_IFREG | int(item["mode"])) << 16
                source = clone_root / str(item["path"])
                with open(filesystem_path(source), "rb") as handle:
                    archive.writestr(info, handle.read())
    except (OSError, zipfile.BadZipFile) as exc:
        raise FinalAdmissionError("deterministic archive cannot be written") from exc


def _digest_bytes(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    count = 0
    try:
        with open(filesystem_path(path), "rb") as handle:
            while True:
                chunk = handle.read(128 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                count += len(chunk)
    except OSError as exc:
        raise FinalAdmissionError(f"archive cannot be read: {path}") from exc
    return count, digest.hexdigest()


def verify_final_archive(
    archive_path: str | os.PathLike[str],
    file_manifest: Sequence[Mapping[str, Any]],
    *,
    archive_prefix: str = "promin",
) -> dict[str, Any]:
    """Verify a deterministic candidate archive against a typed file manifest."""

    prefix = _archive_prefix(archive_prefix)
    expected = [dict(item) for item in file_manifest]
    if not expected or len(expected) > MAX_ADMISSION_FILES:
        raise FinalAdmissionError("archive verification requires a bounded non-empty file manifest")
    expected_names = [f"{prefix}/{item['path']}" for item in expected]
    if expected_names != sorted(expected_names, key=_sort_key):
        raise FinalAdmissionError("file manifest is not canonically sorted")
    for item in expected:
        if set(item) != {"path", "bytes", "sha256", "mode"}:
            raise FinalAdmissionError("file manifest member has unexpected fields")
        _relative_path(item["path"], "file manifest path")
        if not isinstance(item["bytes"], int) or isinstance(item["bytes"], bool) or item["bytes"] < 0:
            raise FinalAdmissionError("file manifest byte count is invalid")
        if not isinstance(item["sha256"], str) or _SHA256.fullmatch(item["sha256"]) is None:
            raise FinalAdmissionError("file manifest sha256 is invalid")
        if item["mode"] not in CANONICAL_ARCHIVE_MODES:
            raise FinalAdmissionError("file manifest mode is invalid")
    try:
        with zipfile.ZipFile(filesystem_path(archive_path), "r") as archive:
            infos = archive.infolist()
            if archive.comment != b"" or [info.filename for info in infos] != expected_names:
                raise FinalAdmissionError("archive names or ordering are not deterministic")
            for info, item in zip(infos, expected, strict=True):
                mode = (info.external_attr >> 16) & 0o777
                if (
                    info.is_dir()
                    or info.date_time != FIXED_ZIP_TIMESTAMP
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.create_system != 3
                    or mode != item["mode"]
                    or info.file_size != item["bytes"]
                ):
                    raise FinalAdmissionError(f"archive entry metadata differs: {info.filename}")
                payload = archive.read(info)
                if hashlib.sha256(payload).hexdigest() != item["sha256"]:
                    raise FinalAdmissionError(f"archive entry digest differs: {info.filename}")
    except (OSError, zipfile.BadZipFile) as exc:
        raise FinalAdmissionError("archive cannot be verified") from exc
    archive_bytes, archive_sha256 = _digest_bytes(Path(archive_path))
    return {
        "archive_bytes": archive_bytes,
        "archive_sha256": archive_sha256,
        "entry_count": len(expected),
        "tree_digest": _tree_digest(expected),
    }


def _copy_new_file(source: Path, destination: Path) -> None:
    try:
        with open(filesystem_path(source), "rb") as reader, open(
            filesystem_path(destination), "xb"
        ) as writer:
            shutil.copyfileobj(reader, writer, length=128 * 1024)
    except OSError as exc:
        raise FinalAdmissionError(f"candidate archive cannot be published: {destination.name}") from exc


def _write_new_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = canonical_bytes(dict(value))
    try:
        with open(filesystem_path(path), "xb") as handle:
            handle.write(payload)
    except OSError as exc:
        raise FinalAdmissionError(f"admission receipt cannot be published: {path.name}") from exc


def admit_final_package(
    source_root: str | os.PathLike[str],
    output_root: str | os.PathLike[str],
    *,
    tracked_paths: Iterable[str],
    archive_name: str = "promin-standard-candidate.zip",
    archive_prefix: str = "promin",
) -> dict[str, Any]:
    """Build two external clones and admit their byte-identical candidate archive.

    ``tracked_paths`` is the caller-supplied exact tracked boundary.  Unknown
    source files fail closed; only explicitly classified operational/generated
    paths may appear in the delete manifest.  The function never writes under
    ``source_root`` and records no acceptance pass credit.
    """

    source = _require_real_directory(source_root, "source root")
    output = _require_real_directory(output_root, "external output root")
    if _source_is_ancestor_of(output, source):
        raise FinalAdmissionError("external output root must not be source root or a source descendant")
    paths = _validated_tracked_paths(tracked_paths)
    candidate_name = _archive_name(archive_name)
    prefix = _archive_prefix(archive_prefix)
    candidate_path = output / candidate_name
    receipt_path = output / "final-package-admission.json"
    if candidate_path.exists() or receipt_path.exists():
        raise FinalAdmissionError("external output already contains a candidate or admission receipt")
    files, deletes, source_before = _source_boundary(source, paths)
    tree_digest = _tree_digest(files)
    workspace = Path(tempfile.mkdtemp(prefix="promin-final-admission-", dir=filesystem_path(output)))
    try:
        clone_a = workspace / "clone-a"
        clone_b = workspace / "clone-b"
        archive_a = workspace / "candidate-a.zip"
        archive_b = workspace / "candidate-b.zip"
        _copy_clone(source, clone_a, files)
        _copy_clone(source, clone_b, files)
        clone_a_tree = _verify_clone(clone_a, files)
        clone_b_tree = _verify_clone(clone_b, files)
        _write_archive(clone_a, archive_a, files, prefix)
        _write_archive(clone_b, archive_b, files, prefix)
        verification_a = verify_final_archive(archive_a, files, archive_prefix=prefix)
        verification_b = verify_final_archive(archive_b, files, archive_prefix=prefix)
        archive_a_bytes = archive_a.read_bytes()
        archive_b_bytes = archive_b.read_bytes()
        if archive_a_bytes != archive_b_bytes:
            raise FinalAdmissionError("independent archive generations are not byte-identical")
        _, _, source_after = _source_boundary(source, paths)
        if source_before != source_after:
            raise FinalAdmissionError("source root changed during external admission")
        _copy_new_file(archive_a, candidate_path)
        published_verification = verify_final_archive(candidate_path, files, archive_prefix=prefix)
        record: dict[str, Any] = {
            "record_type": "FinalPackageAdmission",
            "schema": FINAL_ADMISSION_SCHEMA,
            "status": "candidate",
            "archive_name": candidate_name,
            "archive_prefix": prefix,
            "cloneable_tracked_boundary": True,
            "sorted_file_manifest": True,
            "sorted_delete_manifest": True,
            "byte_count_and_sha256_per_file": True,
            "file_mode_identity": True,
            "tree_digest": tree_digest,
            "source_file_manifest": files,
            "delete_manifest": deletes,
            "operational_state_excluded": True,
            "independent_generation_a": {
                "clone_tree_digest": clone_a_tree,
                **verification_a,
            },
            "independent_generation_b": {
                "clone_tree_digest": clone_b_tree,
                **verification_b,
            },
            "byte_identical_archives": True,
            "self_verification": {
                "archive_sha256": published_verification["archive_sha256"],
                "archive_bytes": published_verification["archive_bytes"],
                "entry_count": published_verification["entry_count"],
                "tree_digest": published_verification["tree_digest"],
                "valid": True,
            },
            "source_unchanged": True,
            "acceptance_pass": False,
            "pass_credit": False,
            "product_acceptance_pass": False,
        }
        _write_new_json(receipt_path, record)
        return record
    finally:
        shutil.rmtree(filesystem_path(workspace), ignore_errors=True)
