"""Locate the immutable promin standard bundle in source and installed layouts.

The operational runtime must not depend on the caller's current working directory.
Resolution is explicit and deterministic:

1. ``PROMIN_BUNDLE_ROOT`` when set by a host/package verifier;
2. the source/distribution root adjacent to the Python package;
3. ``<sys.prefix>/share/promin`` for installed data-file layouts.

A candidate is accepted only when the canonical Core manifest and bundled preset
are both present.  The function returns a resolved real directory and caches only
that validated path for the lifetime of the process.
"""

from __future__ import annotations

from functools import lru_cache
import os
from pathlib import Path
import sys


class ResourceError(RuntimeError):
    """Raised when the canonical standard bundle cannot be located."""


def _is_bundle_root(path: Path) -> bool:
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return False
    if resolved.is_symlink() or not resolved.is_dir():
        return False
    return (
        (resolved / "core" / "promin.manifest.json").is_file()
        and (resolved / "presets" / "semantic-morok-tower.json").is_file()
    )


@lru_cache(maxsize=1)
def bundle_root() -> Path:
    """Return the validated root containing ``core/`` and ``presets/``.

    The environment override is deliberately explicit.  It is useful for clean
    installed-distribution verification and embedding promin into another tool,
    while source-tree execution remains zero-configuration.
    """

    candidates: list[Path] = []
    override = os.environ.get("PROMIN_BUNDLE_ROOT")
    if override:
        candidates.append(Path(override))

    package_dir = Path(__file__).resolve().parent
    candidates.extend(
        (
            package_dir.parent,
            package_dir / "_bundle",
            Path(sys.prefix) / "share" / "promin",
            Path(sys.base_prefix) / "share" / "promin",
        )
    )

    seen: set[Path] = set()
    for candidate in candidates:
        try:
            normalized = candidate.resolve()
        except OSError:
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        if _is_bundle_root(normalized):
            return normalized

    rendered = ", ".join(str(path) for path in candidates)
    raise ResourceError(f"canonical promin bundle is unavailable; checked: {rendered}")
