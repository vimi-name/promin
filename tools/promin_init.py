"""Thin compatibility entry points for the canonical Promin initializer."""

from __future__ import annotations

import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) in sys.path:
    sys.path.remove(str(PACKAGE_ROOT))
sys.path.insert(0, str(PACKAGE_ROOT))

from promin.init import (
    ActivationGuard,
    InitPreflightReceipt,
    InitRequest,
    apply_explicit_init_plan as apply_plan,
    build_explicit_init_plan as make_plan,
    initialize_project,
)

__all__ = [
    "ActivationGuard",
    "InitPreflightReceipt",
    "InitRequest",
    "apply_plan",
    "initialize_project",
    "make_plan",
]
