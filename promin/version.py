"""Canonical version access for promin.

The Core manifest is the sole authoritative version owner.  All runtime and
packaging surfaces obtain the version through this module instead of embedding a
second literal.
"""

from __future__ import annotations

from functools import lru_cache
import json
import re
from typing import Any

from .resources import bundle_root

_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


class VersionError(RuntimeError):
    """Raised when the canonical manifest version is missing or malformed."""


@lru_cache(maxsize=1)
def standard_version() -> str:
    path = bundle_root() / "core" / "promin.manifest.json"
    try:
        value: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VersionError("canonical promin manifest is unreadable") from exc
    version = value.get("version") if isinstance(value, dict) else None
    if not isinstance(version, str) or _SEMVER.fullmatch(version) is None:
        raise VersionError("canonical promin manifest version is not structural SemVer")
    return version


@lru_cache(maxsize=1)
def python_distribution_version() -> str:
    """Return the PEP 440 projection of the canonical standard version.

    ``promin.__version__`` and the CLI intentionally expose canonical SemVer,
    while Python package metadata must use PEP 440.  Both values are derived
    from the same manifest owner.
    """

    version = standard_version()
    for label, marker in (("alpha", "a"), ("beta", "b"), ("rc", "rc")):
        match = re.fullmatch(
            rf"([0-9]+\.[0-9]+\.[0-9]+)-{label}\.([1-9][0-9]*)",
            version,
        )
        if match is not None:
            return f"{match.group(1)}{marker}{match.group(2)}"
    return version
