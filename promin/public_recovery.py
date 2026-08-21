"""Strict public clean-recovery workflow."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .canonical import canonical_bytes, digest_value, load_json_strict
from .clean_reinitialization import (
    StandardInitializationPublication,
    StandardInitializationRequest,
    clean_reinitialize_project,
    prepare_clean_reinitialization,
)
from .init import InitRequest, initialize_project
from .platform_paths import PlatformPathError, resolve_contained_path, resolve_identity_path
from .recovery import OwnerConfirmation, PublishedCleanReinitialization


_SCHEMA = "promin.clean-recovery-cli-input.v1"
_RECORD = "CleanRecoveryCliInput"
_KEYS = frozenset({
    "schema", "record_type", "package_root", "project_identity", "owner_confirmation",
    "init_input", "authority_granted", "pass_credit", "acceptance_pass", "product_acceptance_pass",
})
_INIT_KEYS = frozenset({
    "standard_bundle", "preset_path", "project_plan", "standards_plan", "technologies_plan",
    "licenses_plan", "authority_plan", "activation_proofs",
})


class PublicRecoveryError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CleanRecoveryCliRequest:
    package_root: Path
    project_identity: str
    owner_confirmation: OwnerConfirmation | None
    init_input: Mapping[str, object] | None


def _path(value: object, *, base: Path, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise PublicRecoveryError(f"{label} must be a non-empty path")
    selected = Path(value)
    try:
        if selected.is_absolute():
            return resolve_identity_path(selected, strict=True)
        return resolve_contained_path(selected, root=base)
    except (PlatformPathError, OSError) as exc:
        raise PublicRecoveryError(f"{label} is unsafe or unavailable") from exc


def _outside_control(path: Path, project_root: Path, label: str) -> None:
    for control in (project_root / ".promin", project_root / ".promin-host"):
        try:
            path.relative_to(control)
        except ValueError:
            continue
        raise PublicRecoveryError(f"{label} must be outside prior recovery roots")


def _confirmation(value: object) -> OwnerConfirmation | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "schema", "record_type", "owner_id", "confirmation_id", "intent_digest", "confirmed_at_ns", "approved", "confirmation_digest"
    }:
        raise PublicRecoveryError("owner_confirmation is not canonical")
    try:
        candidate = OwnerConfirmation(
            owner_id=value["owner_id"], confirmation_id=value["confirmation_id"],
            intent_digest=value["intent_digest"], confirmed_at_ns=value["confirmed_at_ns"],
            approved=value["approved"],
        )
    except Exception as exc:
        raise PublicRecoveryError("owner_confirmation is invalid") from exc
    if value != candidate.to_record():
        raise PublicRecoveryError("owner_confirmation is not exact")
    return candidate


def load_clean_recovery_request(path: Path, *, project_root: Path) -> CleanRecoveryCliRequest:
    try:
        value = load_json_strict(path, root=path.parent)
        if path.read_bytes() != canonical_bytes(value):
            raise PublicRecoveryError("request must be canonical JSON")
    except PublicRecoveryError:
        raise
    except Exception as exc:
        raise PublicRecoveryError("request cannot be loaded as strict JSON") from exc
    if not isinstance(value, dict) or set(value) != _KEYS:
        raise PublicRecoveryError("request keys are not canonical")
    if value["schema"] != _SCHEMA or value["record_type"] != _RECORD:
        raise PublicRecoveryError("request schema is invalid")
    for field in ("authority_granted", "pass_credit", "acceptance_pass", "product_acceptance_pass"):
        if type(value[field]) is not bool or value[field] is not False:
            raise PublicRecoveryError(f"request {field} must remain false")
    identity = value["project_identity"]
    if not isinstance(identity, str) or len(identity) != 64 or any(c not in "0123456789abcdef" for c in identity):
        raise PublicRecoveryError("project_identity must be a lowercase SHA-256 digest")
    base = path.parent.resolve()
    package = _path(value["package_root"], base=base, label="package_root")
    _outside_control(package, project_root.resolve(), "package_root")
    init_input = value["init_input"]
    if init_input is not None:
        if not isinstance(init_input, dict) or not set(init_input).issubset(_INIT_KEYS):
            raise PublicRecoveryError("init_input keys are invalid")
        if set(init_input) - {"activation_proofs"} != _INIT_KEYS - {"activation_proofs"}:
            raise PublicRecoveryError("init_input is incomplete")
        for key in _INIT_KEYS - {"activation_proofs"}:
            resolved = _path(init_input[key], base=base, label=f"init_input.{key}")
            _outside_control(resolved, project_root.resolve(), f"init_input.{key}")
    if init_input is not None:
        init_input = dict(init_input)
        for key in _INIT_KEYS - {"activation_proofs"}:
            init_input[key] = str(_path(init_input[key], base=base, label=f"init_input.{key}"))
    return CleanRecoveryCliRequest(package, identity, _confirmation(value["owner_confirmation"]), init_input)


def _claims() -> dict[str, bool]:
    return {"authority_granted": False, "pass_credit": False, "acceptance_pass": False, "product_acceptance_pass": False}


def plan_clean_recovery(request: CleanRecoveryCliRequest, *, project_root: Path) -> dict[str, object]:
    preparation = prepare_clean_reinitialization(request.package_root, project_identity=request.project_identity)
    return {"record_type": "CleanRecoveryPlan", "preparation": preparation.to_record(), "claims": _claims(), **_claims()}


def apply_clean_recovery(request: CleanRecoveryCliRequest, *, project_root: Path) -> dict[str, object]:
    if request.owner_confirmation is None or request.init_input is None:
        raise PublicRecoveryError("--apply requires owner_confirmation and complete init_input")
    preparation = prepare_clean_reinitialization(request.package_root, project_identity=request.project_identity)
    if request.owner_confirmation.intent_digest != preparation.intent.intent_digest:
        raise PublicRecoveryError("owner_confirmation does not match preparation intent")
    base = Path.cwd()  # replaced by request path parent through resolved input values below
    values = request.init_input
    def initializer(init_request: StandardInitializationRequest) -> StandardInitializationPublication:
        kwargs = {key: _path(values[key], base=base, label=f"init_input.{key}") for key in _INIT_KEYS - {"activation_proofs"}}
        proofs = values.get("activation_proofs")
        result = initialize_project(InitRequest(project_root=project_root, activation_proofs=proofs, portable_docs_shell=init_request.docs_shell, **kwargs))
        activation_digest = result.context.activation_digest
        published = PublishedCleanReinitialization(
            intent_digest=init_request.intent.intent_digest,
            package_digest=init_request.intent.package_digest,
            extension_admission_digest=init_request.intent.extension_admission_digest,
            activation_digest=activation_digest,
        )
        def verify(candidate: PublishedCleanReinitialization) -> bool:
            from .init import ActivationGuard
            context = ActivationGuard(project_root).verify()
            return (
                candidate == published
                and context.activation_digest == activation_digest
                and candidate.intent_digest == init_request.intent.intent_digest
                and candidate.package_digest == preparation.package.tree_sha256
                and candidate.extension_admission_digest == init_request.intent.extension_admission_digest
            )
        return StandardInitializationPublication(published, verify)
    result = clean_reinitialize_project(project_root, request.package_root, project_identity=request.project_identity, owner_confirmation=request.owner_confirmation, standard_initializer=initializer)
    return {**result.to_record(), "claims": _claims()}
