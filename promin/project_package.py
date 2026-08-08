"""Typed, digest-bound portable project packages for clean reinitialization.

The base ``project-package.json`` deliberately stays compatible with
``promin.project-package.v1``.  Its exact, small schema is complemented by a
second canonical record named ``project-package-content.json``.  The companion
record binds every portable seed member to a source path, install target,
canonical mode, byte count, SHA-256 digest, and a deterministic tree digest.
The only tracked control root is ``.promin/docs``; typed extensions live below
``.promin/docs/extensions/<id>/`` and never create a sibling control root.

This module is intentionally read-only.  It validates a package directory; it
does not initialize a project, import operational state, or replay progress.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .canonical import CanonicalError, canonical_bytes, digest_bytes, parse_json_strict
from .platform_paths import PlatformPathError, filesystem_path, resolve_contained_path


PROJECT_PACKAGE_SCHEMA = "promin.project-package.v1"
PROJECT_PACKAGE_CONTENT_SCHEMA = "promin.project-package-content.v1"
PROJECT_PACKAGE_MANIFEST_NAME = "project-package.json"
PROJECT_PACKAGE_CONTENT_NAME = "project-package-content.json"

MAX_MANIFEST_BYTES = 1 * 1024 * 1024
MAX_PACKAGE_MEMBERS = 512
MAX_MEMBER_BYTES = 512 * 1024
MAX_PACKAGE_BYTES = 8 * 1024 * 1024
MAX_PATH_BYTES = 512
MAX_PATH_COMPONENTS = 16
MAX_HOST_INTEGRATIONS = 64

CANONICAL_MEMBER_MODES = frozenset({0o644, 0o755})
PORTABLE_SURFACE_KINDS = frozenset({"portable-doc", "typed-extension"})

REQUIRED_OPERATIONAL_ROOTS = frozenset(
    {
        ".promin/cache",
        ".promin/evidence",
        ".promin/init",
        ".promin/leases",
        ".promin/locks",
        ".promin/providers",
        ".promin/state",
    }
)

_BASE_KEYS = frozenset(
    {
        "schema",
        "package_id",
        "package_version",
        "standard_version",
        "default_profile",
        "profiles",
        "tracked_extension_roots",
        "operational_roots",
        "state_migration_supported",
        "previous_progress_replay_supported",
    }
)
_CONTENT_KEYS = frozenset(
    {
        "schema",
        "package_id",
        "package_version",
        "seed_surfaces",
        "host_integrations",
        "members",
        "tree_sha256",
    }
)
_SEED_SURFACE_KEYS = frozenset(
    {"surface_id", "surface_kind", "source_root", "target_root"}
)
_HOST_INTEGRATION_KEYS = frozenset(
    {"integration_id", "integration_kind", "enabled_by_default"}
)
_MEMBER_KEYS = frozenset(
    {"source_path", "target_path", "member_class", "bytes", "sha256", "mode"}
)
_TREE_MEMBER_KEYS = (
    "source_path",
    "target_path",
    "member_class",
    "bytes",
    "sha256",
    "mode",
)

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_PATH_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
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


class ProjectPackageError(ValueError):
    """Raised when a portable project package is not strict or complete."""


@dataclass(frozen=True, slots=True)
class VerifiedProjectPackage:
    """Read-only receipt for one fully verified portable package."""

    package_root: Path
    package_id: str
    package_version: str
    standard_version: str
    default_profile: str
    member_count: int
    total_bytes: int
    tree_sha256: str
    tracked_extension_roots: tuple[str, ...]
    operational_roots: tuple[str, ...]

    def receipt(self) -> dict[str, Any]:
        """Return a portable verification receipt without local filesystem paths."""

        return {
            "record_type": "VerifiedProjectPackage",
            "schema": PROJECT_PACKAGE_CONTENT_SCHEMA,
            "package_id": self.package_id,
            "package_version": self.package_version,
            "standard_version": self.standard_version,
            "default_profile": self.default_profile,
            "member_count": self.member_count,
            "total_bytes": self.total_bytes,
            "tree_sha256": self.tree_sha256,
            "tracked_extension_roots": list(self.tracked_extension_roots),
            "operational_roots": list(self.operational_roots),
            "state_migration_supported": False,
            "previous_progress_replay_supported": False,
            "acceptance_pass": False,
            "pass_credit": False,
            "product_acceptance_pass": False,
        }


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
        raise ProjectPackageError(f"{label} cannot be inspected: {path}") from exc


def _require_real_directory(path: str | os.PathLike[str], label: str) -> Path:
    candidate = Path(path)
    inspected = _lstat(candidate, label)
    if _is_link_or_reparse(candidate, inspected) or not stat.S_ISDIR(inspected.st_mode):
        raise ProjectPackageError(f"{label} must be a real directory")
    try:
        resolved = resolve_contained_path(candidate, root=candidate.parent)
    except PlatformPathError as exc:
        raise ProjectPackageError(f"{label} cannot be resolved safely") from exc
    resolved_inspected = _lstat(resolved, label)
    if _is_link_or_reparse(resolved, resolved_inspected) or not stat.S_ISDIR(
        resolved_inspected.st_mode
    ):
        raise ProjectPackageError(f"{label} must resolve to a real directory")
    return resolved


def _require_exact_keys(value: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ProjectPackageError(f"{label} must contain exactly {sorted(expected)}")
    return value


def _text(value: Any, label: str, *, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ProjectPackageError(f"{label} must be a bounded non-empty UTF-8 string")
    if unicodedata.normalize("NFC", value) != value:
        raise ProjectPackageError(f"{label} must be NFC")
    return value


def _identifier(value: Any, label: str) -> str:
    text = _text(value, label, maximum=64)
    if _IDENTIFIER.fullmatch(text) is None:
        raise ProjectPackageError(f"{label} must be a lowercase portable identifier")
    return text


def _version(value: Any, label: str) -> str:
    text = _text(value, label, maximum=128)
    if _SEMVER.fullmatch(text) is None:
        raise ProjectPackageError(f"{label} must be semantic-version text")
    return text


def _relative_path(value: Any, label: str) -> str:
    text = _text(value, label, maximum=MAX_PATH_BYTES)
    if "\\" in text or "\x00" in text or text.startswith("/") or text.endswith("/"):
        raise ProjectPackageError(f"{label} must be a normalized relative POSIX path")
    components = text.split("/")
    if len(components) > MAX_PATH_COMPONENTS or any(
        not component or component in {".", ".."} for component in components
    ):
        raise ProjectPackageError(f"{label} has invalid path components")
    for component in components:
        if ":" in component or component.endswith((".", " ")):
            raise ProjectPackageError(f"{label} is not portable to Windows")
        if component != ".promin" and _PATH_COMPONENT.fullmatch(component) is None:
            raise ProjectPackageError(f"{label} has unsupported path characters")
        if component.split(".", 1)[0].upper() in _WINDOWS_RESERVED:
            raise ProjectPackageError(f"{label} uses a Windows reserved name")
    return text


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _paths_overlap(left: str, right: str) -> bool:
    return _under(left, right) or _under(right, left)


def _require_sorted_unique_strings(values: Any, label: str) -> tuple[str, ...]:
    if not isinstance(values, list) or not values:
        raise ProjectPackageError(f"{label} must be a non-empty list")
    normalized = tuple(_text(value, f"{label}[{index}]") for index, value in enumerate(values))
    if tuple(sorted(normalized, key=_sort_key)) != normalized:
        raise ProjectPackageError(f"{label} must use canonical UTF-8 sort order")
    folded = [value.casefold() for value in normalized]
    if len(set(folded)) != len(folded):
        raise ProjectPackageError(f"{label} contains duplicate portable values")
    return normalized


def _tracked_root(value: Any, label: str) -> str:
    root = _relative_path(value, label)
    if root == ".promin/docs":
        return root
    raise ProjectPackageError(f"{label} must be the sole tracked root .promin/docs")


def _typed_extension_target_root(value: Any, label: str) -> str:
    root = _relative_path(value, label)
    parts = root.split("/")
    if (
        len(parts) == 4
        and parts[:3] == [".promin", "docs", "extensions"]
        and _IDENTIFIER.fullmatch(parts[3]) is not None
    ):
        return root
    raise ProjectPackageError(
        f"{label} must be .promin/docs/extensions/<typed-id>"
    )


def _operational_root(value: Any, label: str) -> str:
    root = _relative_path(value, label)
    if not root.startswith(".promin/") or root in {".promin/docs", ".promin/extensions"}:
        raise ProjectPackageError(f"{label} must be an operational .promin root")
    return root


def _canonical_record(root: Path, name: str) -> dict[str, Any]:
    path = root / name
    try:
        resolved = resolve_contained_path(path, root=root, require_regular=True)
    except PlatformPathError as exc:
        raise ProjectPackageError(f"package record {name} is not a regular local file") from exc
    try:
        size = os.stat(filesystem_path(resolved), follow_symlinks=False).st_size
    except OSError as exc:
        raise ProjectPackageError(f"package record {name} cannot be measured") from exc
    if size > MAX_MANIFEST_BYTES:
        raise ProjectPackageError(f"package record {name} exceeds {MAX_MANIFEST_BYTES} bytes")
    try:
        with open(filesystem_path(resolved), "rb") as handle:
            payload = handle.read(MAX_MANIFEST_BYTES + 1)
    except OSError as exc:
        raise ProjectPackageError(f"package record {name} cannot be read") from exc
    if len(payload) != size or len(payload) > MAX_MANIFEST_BYTES:
        raise ProjectPackageError(f"package record {name} changed while being read")
    try:
        value = parse_json_strict(payload)
    except CanonicalError as exc:
        raise ProjectPackageError(f"package record {name} is not strict canonical JSON") from exc
    if not isinstance(value, dict) or canonical_bytes(value) != payload:
        raise ProjectPackageError(f"package record {name} must use exact canonical JSON bytes")
    return value


def _direct_entries(root: Path) -> set[str]:
    try:
        entries = {entry.name for entry in os.scandir(filesystem_path(root))}
    except OSError as exc:
        raise ProjectPackageError("package root cannot be enumerated") from exc
    return entries


def _walk_real_tree(root: Path, prefix: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return regular files and directories, rejecting every link or special node."""

    _require_real_directory(root, prefix)
    files: list[str] = []
    directories: list[str] = [prefix]

    def visit(directory: Path, relative: str) -> None:
        try:
            entries = list(os.scandir(filesystem_path(directory)))
        except OSError as exc:
            raise ProjectPackageError(f"package tree cannot be enumerated: {relative}") from exc
        entries.sort(key=lambda entry: _sort_key(entry.name))
        for entry in entries:
            path = directory / entry.name
            try:
                inspected = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise ProjectPackageError(f"package tree entry cannot be inspected: {relative}") from exc
            item_relative = f"{relative}/{entry.name}"
            _relative_path(item_relative, "package tree path")
            if _is_link_or_reparse(path, inspected):
                raise ProjectPackageError(f"package tree contains a symbolic link or reparse point: {item_relative}")
            if stat.S_ISDIR(inspected.st_mode):
                directories.append(item_relative)
                visit(path, item_relative)
            elif stat.S_ISREG(inspected.st_mode):
                files.append(item_relative)
            else:
                raise ProjectPackageError(f"package tree contains a non-regular special entry: {item_relative}")

    visit(root, prefix)
    return tuple(files), tuple(directories)


def _file_digest(path: Path, root: Path) -> tuple[int, str]:
    try:
        resolved = resolve_contained_path(path, root=root, require_regular=True)
        before = os.stat(filesystem_path(resolved), follow_symlinks=False)
    except (OSError, PlatformPathError) as exc:
        raise ProjectPackageError(f"package member is not a regular contained file: {path}") from exc
    if before.st_size > MAX_MEMBER_BYTES:
        raise ProjectPackageError(f"package member exceeds {MAX_MEMBER_BYTES} bytes: {path}")
    digest = hashlib.sha256()
    try:
        with open(filesystem_path(resolved), "rb") as handle:
            while True:
                chunk = handle.read(64 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise ProjectPackageError(f"package member cannot be read: {path}") from exc
    try:
        after = os.stat(filesystem_path(resolved), follow_symlinks=False)
    except OSError as exc:
        raise ProjectPackageError(f"package member disappeared while being read: {path}") from exc
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_identity != after_identity:
        raise ProjectPackageError(f"package member changed while being digested: {path}")
    return before.st_size, digest.hexdigest()


def _tree_rows(members: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {key: member[key] for key in _TREE_MEMBER_KEYS}
        for member in sorted(
            members,
            key=lambda member: (_sort_key(str(member["target_path"])), _sort_key(str(member["source_path"]))),
        )
    ]


def project_package_tree_digest(members: Sequence[Mapping[str, Any]]) -> str:
    """Return the canonical portable-member tree identity for a content record."""

    return digest_bytes(canonical_bytes(_tree_rows(members)))


def _validate_base(value: Any) -> dict[str, Any]:
    base = _require_exact_keys(value, _BASE_KEYS, PROJECT_PACKAGE_MANIFEST_NAME)
    if base["schema"] != PROJECT_PACKAGE_SCHEMA:
        raise ProjectPackageError("project package schema is not supported")
    _identifier(base["package_id"], "package_id")
    _version(base["package_version"], "package_version")
    _version(base["standard_version"], "standard_version")
    profiles = _require_sorted_unique_strings(base["profiles"], "profiles")
    default_profile = _text(base["default_profile"], "default_profile", maximum=128)
    if default_profile not in profiles:
        raise ProjectPackageError("default_profile must be declared by profiles")
    roots = tuple(
        _tracked_root(item, f"tracked_extension_roots[{index}]")
        for index, item in enumerate(base["tracked_extension_roots"])
    )
    if not isinstance(base["tracked_extension_roots"], list) or not roots:
        raise ProjectPackageError("tracked_extension_roots must be a non-empty list")
    if tuple(sorted(roots, key=_sort_key)) != roots or len({root.casefold() for root in roots}) != len(roots):
        raise ProjectPackageError("tracked_extension_roots must be sorted and unique")
    if roots != (".promin/docs",):
        raise ProjectPackageError(
            "tracked_extension_roots must contain only the tracked .promin/docs root"
        )
    operational = tuple(
        _operational_root(item, f"operational_roots[{index}]")
        for index, item in enumerate(base["operational_roots"])
    )
    if not isinstance(base["operational_roots"], list) or not operational:
        raise ProjectPackageError("operational_roots must be a non-empty list")
    if tuple(sorted(operational, key=_sort_key)) != operational or len(
        {root.casefold() for root in operational}
    ) != len(operational):
        raise ProjectPackageError("operational_roots must be sorted and unique")
    if not REQUIRED_OPERATIONAL_ROOTS <= set(operational):
        missing = sorted(REQUIRED_OPERATIONAL_ROOTS - set(operational), key=_sort_key)
        raise ProjectPackageError(f"operational_roots omit required roots: {missing}")
    for index, root in enumerate(roots):
        for other in roots[index + 1 :]:
            if _paths_overlap(root, other):
                raise ProjectPackageError("tracked_extension_roots may not overlap")
    for root in roots:
        if any(_paths_overlap(root, operational_root) for operational_root in operational):
            raise ProjectPackageError("tracked roots may not overlap operational roots")
    if base["state_migration_supported"] is not False:
        raise ProjectPackageError("state_migration_supported must be false")
    if base["previous_progress_replay_supported"] is not False:
        raise ProjectPackageError("previous_progress_replay_supported must be false")
    return base


def _validate_content(value: Any, base: Mapping[str, Any], package_root: Path) -> tuple[tuple[dict[str, Any], ...], int, str]:
    content = _require_exact_keys(value, _CONTENT_KEYS, PROJECT_PACKAGE_CONTENT_NAME)
    if content["schema"] != PROJECT_PACKAGE_CONTENT_SCHEMA:
        raise ProjectPackageError("project package content schema is not supported")
    if content["package_id"] != base["package_id"] or content["package_version"] != base["package_version"]:
        raise ProjectPackageError("content package identity does not match project-package.json")
    surfaces_value = content["seed_surfaces"]
    if not isinstance(surfaces_value, list) or not surfaces_value or len(surfaces_value) > MAX_PACKAGE_MEMBERS:
        raise ProjectPackageError("seed_surfaces must be a bounded non-empty list")
    tracked_roots = set(base["tracked_extension_roots"])
    surfaces: list[dict[str, str]] = []
    seen_surface_ids: set[str] = set()
    source_roots: list[str] = []
    for index, raw_surface in enumerate(surfaces_value):
        surface = _require_exact_keys(raw_surface, _SEED_SURFACE_KEYS, f"seed_surfaces[{index}]")
        surface_id = _identifier(surface["surface_id"], f"seed_surfaces[{index}].surface_id")
        if surface_id in seen_surface_ids:
            raise ProjectPackageError("seed surface identifiers must be unique")
        seen_surface_ids.add(surface_id)
        kind = _identifier(surface["surface_kind"], f"seed_surfaces[{index}].surface_kind")
        if kind not in PORTABLE_SURFACE_KINDS:
            raise ProjectPackageError("seed surface has unsupported portable kind")
        source_root = _relative_path(surface["source_root"], f"seed_surfaces[{index}].source_root")
        if not source_root.startswith("seeds/") or source_root == "seeds":
            raise ProjectPackageError("seed surface source_root must be below seeds/")
        if kind == "portable-doc":
            target_root = _tracked_root(
                surface["target_root"], f"seed_surfaces[{index}].target_root"
            )
        else:
            target_root = _typed_extension_target_root(
                surface["target_root"], f"seed_surfaces[{index}].target_root"
            )
        if not any(_under(target_root, tracked_root) for tracked_root in tracked_roots):
            raise ProjectPackageError("seed surface target_root is outside .promin/docs")
        if kind == "portable-doc" and target_root != ".promin/docs":
            raise ProjectPackageError("portable-doc surfaces may target only .promin/docs")
        if kind == "typed-extension" and not target_root.startswith(
            ".promin/docs/extensions/"
        ):
            raise ProjectPackageError("typed-extension surfaces require a typed docs extension root")
        source_roots.append(source_root)
        surfaces.append(
            {
                "surface_id": surface_id,
                "surface_kind": kind,
                "source_root": source_root,
                "target_root": target_root,
            }
        )
    if tuple(surface["surface_id"] for surface in surfaces) != tuple(
        sorted((surface["surface_id"] for surface in surfaces), key=_sort_key)
    ):
        raise ProjectPackageError("seed_surfaces must use canonical surface_id order")
    for index, root in enumerate(source_roots):
        if any(_paths_overlap(root, other) for other in source_roots[index + 1 :]):
            raise ProjectPackageError("seed surface source roots may not overlap")
    typed_target_roots = [
        surface["target_root"]
        for surface in surfaces
        if surface["surface_kind"] == "typed-extension"
    ]
    if len(set(typed_target_roots)) != len(typed_target_roots):
        raise ProjectPackageError("typed extension target roots must be unique")

    integrations = content["host_integrations"]
    if not isinstance(integrations, list) or len(integrations) > MAX_HOST_INTEGRATIONS:
        raise ProjectPackageError("host_integrations must be a bounded list")
    integration_ids: list[str] = []
    for index, raw_integration in enumerate(integrations):
        integration = _require_exact_keys(raw_integration, _HOST_INTEGRATION_KEYS, f"host_integrations[{index}]")
        integration_id = _identifier(integration["integration_id"], f"host_integrations[{index}].integration_id")
        _identifier(integration["integration_kind"], f"host_integrations[{index}].integration_kind")
        if not isinstance(integration["enabled_by_default"], bool):
            raise ProjectPackageError("host integration enabled_by_default must be boolean")
        integration_ids.append(integration_id)
    if tuple(integration_ids) != tuple(sorted(integration_ids, key=_sort_key)) or len(set(integration_ids)) != len(integration_ids):
        raise ProjectPackageError("host_integrations must be sorted by unique integration_id")

    members_value = content["members"]
    if not isinstance(members_value, list) or not members_value or len(members_value) > MAX_PACKAGE_MEMBERS:
        raise ProjectPackageError("members must be a bounded non-empty list")
    members: list[dict[str, Any]] = []
    sources_seen: set[str] = set()
    targets_seen: set[str] = set()
    total_bytes = 0
    member_order: list[tuple[bytes, bytes]] = []
    surface_member_counts = {surface["surface_id"]: 0 for surface in surfaces}
    for index, raw_member in enumerate(members_value):
        member = _require_exact_keys(raw_member, _MEMBER_KEYS, f"members[{index}]")
        source_path = _relative_path(member["source_path"], f"members[{index}].source_path")
        target_path = _relative_path(member["target_path"], f"members[{index}].target_path")
        member_class = _identifier(member["member_class"], f"members[{index}].member_class")
        if member_class not in PORTABLE_SURFACE_KINDS:
            raise ProjectPackageError("member_class has unsupported portable kind")
        if source_path.casefold() in sources_seen or target_path.casefold() in targets_seen:
            raise ProjectPackageError("members must use unique portable source and target paths")
        sources_seen.add(source_path.casefold())
        targets_seen.add(target_path.casefold())
        if not isinstance(member["bytes"], int) or isinstance(member["bytes"], bool) or not 0 <= member["bytes"] <= MAX_MEMBER_BYTES:
            raise ProjectPackageError("member bytes must be a bounded non-negative integer")
        digest = _text(member["sha256"], f"members[{index}].sha256", maximum=64)
        if _SHA256.fullmatch(digest) is None:
            raise ProjectPackageError("member sha256 must be lowercase hexadecimal")
        mode = member["mode"]
        if not isinstance(mode, int) or isinstance(mode, bool) or mode not in CANONICAL_MEMBER_MODES:
            raise ProjectPackageError("member mode must be one canonical regular-file mode")
        matched = [surface for surface in surfaces if _under(source_path, surface["source_root"])]
        if len(matched) != 1 or source_path == matched[0]["source_root"]:
            raise ProjectPackageError("member source_path must be under exactly one seed surface")
        surface = matched[0]
        if not _under(target_path, surface["target_root"]) or target_path == surface["target_root"]:
            raise ProjectPackageError("member target_path must be under its seed surface target")
        if member_class != surface["surface_kind"]:
            raise ProjectPackageError("member_class must match its seed surface kind")
        if member_class == "portable-doc" and _under(
            target_path, ".promin/docs/extensions"
        ):
            raise ProjectPackageError(
                "portable-doc members may not occupy a typed extension namespace"
            )
        size, actual_digest = _file_digest(package_root / source_path, package_root)
        if size != member["bytes"] or actual_digest != digest:
            raise ProjectPackageError(f"member bytes or sha256 do not match payload: {source_path}")
        total_bytes += size
        if total_bytes > MAX_PACKAGE_BYTES:
            raise ProjectPackageError(f"package members exceed {MAX_PACKAGE_BYTES} bytes")
        surface_member_counts[surface["surface_id"]] += 1
        members.append(
            {
                "source_path": source_path,
                "target_path": target_path,
                "member_class": member_class,
                "bytes": size,
                "sha256": digest,
                "mode": mode,
            }
        )
        member_order.append((_sort_key(target_path), _sort_key(source_path)))
    if member_order != sorted(member_order):
        raise ProjectPackageError("members must use canonical target/source path order")
    if any(count == 0 for count in surface_member_counts.values()):
        raise ProjectPackageError("every seed surface must contain at least one member")

    actual_files, actual_directories = _walk_real_tree(package_root / "seeds", "seeds")
    declared_sources = {member["source_path"] for member in members}
    if set(actual_files) != declared_sources or len(actual_files) != len(declared_sources):
        raise ProjectPackageError("seed file set differs from the exact typed member manifest")
    for directory in actual_directories:
        if not any(_under(directory, root) or _under(root, directory) for root in source_roots):
            raise ProjectPackageError(f"seed tree contains an undeclared directory: {directory}")
    expected_tree = project_package_tree_digest(members)
    tree_sha256 = _text(content["tree_sha256"], "tree_sha256", maximum=64)
    if _SHA256.fullmatch(tree_sha256) is None or tree_sha256 != expected_tree:
        raise ProjectPackageError("project package tree_sha256 does not bind typed members")
    return tuple(members), total_bytes, expected_tree


def verify_project_package(package_root: str | os.PathLike[str]) -> VerifiedProjectPackage:
    """Strictly verify one portable package without changing any project root.

    A valid directory has exactly two canonical JSON records and one real
    ``seeds`` tree.  Operational state cannot appear in that tree because every
    member must target a declared portable root only.
    """

    root = _require_real_directory(package_root, "project package root")
    expected_entries = {
        PROJECT_PACKAGE_MANIFEST_NAME,
        PROJECT_PACKAGE_CONTENT_NAME,
        "seeds",
    }
    actual_entries = _direct_entries(root)
    if actual_entries != expected_entries:
        raise ProjectPackageError(
            f"project package root must contain exactly {sorted(expected_entries)}"
        )
    base = _validate_base(_canonical_record(root, PROJECT_PACKAGE_MANIFEST_NAME))
    members, total_bytes, tree_sha256 = _validate_content(
        _canonical_record(root, PROJECT_PACKAGE_CONTENT_NAME), base, root
    )
    return VerifiedProjectPackage(
        package_root=root,
        package_id=base["package_id"],
        package_version=base["package_version"],
        standard_version=base["standard_version"],
        default_profile=base["default_profile"],
        member_count=len(members),
        total_bytes=total_bytes,
        tree_sha256=tree_sha256,
        tracked_extension_roots=tuple(base["tracked_extension_roots"]),
        operational_roots=tuple(base["operational_roots"]),
    )
