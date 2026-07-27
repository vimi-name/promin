"""Isolated local-control rehydration worker."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
from .experience import apply_plan, resolve_plan
from .refresh import refresh_project


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m promin.rehydrate_worker")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    return parser


def run(root: Path, request_path: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    request_path = request_path.resolve(strict=True)
    value = json.loads(request_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("record_type") != "HostRehydrateRequest":
        raise RuntimeError("invalid host rehydrate request")
    brief = value.get("brief")
    if not isinstance(brief, dict):
        raise RuntimeError("host rehydrate request lacks a brief")
    plan = resolve_plan(root, brief=brief)
    applied = apply_plan(root, plan)
    refreshed = applied.get("refresh") if isinstance(applied, dict) else None
    if not isinstance(refreshed, dict):
        refreshed = refresh_project(root, apply=True)
    return {
        "record_type": "HostRehydrateWorkerResult",
        "status": "applied",
        "plan": plan,
        "applied": applied,
        "refreshed": refreshed,
        "authority": False,
        "pass_credit": False,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        sys.stdout.buffer.write(canonical_bytes(run(args.root, args.request)))
        return 0
    except Exception as exc:
        sys.stderr.buffer.write(canonical_bytes({
            "record_type": "HostRehydrateWorkerFailure",
            "status": "failed",
            "reason": f"{type(exc).__name__}: {str(exc)[:512]}",
            "authority": False,
            "pass_credit": False,
        }))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
