"""Core/schema validation helpers not provided by the public runtime API."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import sys

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) in sys.path:
    sys.path.remove(str(PACKAGE_ROOT))
sys.path.insert(0, str(PACKAGE_ROOT))

from promin.canonical import (
    CanonicalError,
    load_json_strict,
)
from promin.contracts import ContractError, validate_definition, verify_core


ProminError = (CanonicalError, ContractError)


def load_core(root: Path | str) -> Any:
    base = Path(root).resolve()
    core_dir = base / "core"
    if not core_dir.is_dir():
        activation = base / ".promin" / "init" / "activation.json"
        record = load_json_strict(activation, root=base)
        digest = record["core_bundle_digest"].split(":", 1)[-1]
        core_dir = base / ".promin" / "standard" / digest / "core"
    return verify_core(core_dir)


def compile_schema(root: Path | str) -> dict[str, Any]:
    core = load_core(root)
    schema = core.get("contracts.schema.json")
    if not isinstance(schema, dict):
        raise ContractError("verified Core does not expose contracts.schema.json")
    return dict(schema)


def validate_schema_instance(core: Mapping[str, Any], value: dict[str, Any]) -> None:
    schema = core.get("contracts.schema.json")
    if not isinstance(schema, dict):
        raise ContractError("verified Core does not expose contracts.schema.json")
    record_type = value.get("record_type")
    if not isinstance(record_type, str) or record_type not in schema.get("$defs", {}):
        raise ContractError("record_type has no v1 schema definition")
    validate_definition(schema, record_type, value)


__all__ = [
    "ProminError",
    "compile_schema",
    "load_core",
    "validate_schema_instance",
]
