from __future__ import annotations

import hashlib
import importlib.metadata as importlib_metadata
import os
import platform
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager, nullcontext
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import _sqlite3

from .canonical import (
    CanonicalError,
    atomic_write_json,
    canonical_bytes,
    digest_file,
    digest_value,
    ensure_exact_regular_files,
    format_utc_second,
    fsync_directory,
    load_json_strict,
    parse_json_strict,
    parse_utc_second,
    require_regular_file,
)
from .resources import bundle_root
from .provider_store import materialize_from_store
from .platform_paths import (
    PlatformPathError,
    filesystem_path,
    resolve_identity_path,
    resolved_temporary_directory,
    subprocess_path,
)

from .contracts import (
    CORE_FILES,
    INIT_FILES,
    PLAN_FILES,
    ContractBundle,
    ContractError,
    load_contract_bundle,
    compile_project_init,
    validate_definition,
    validate_plan_objects,
)


class InitError(ContractError):
    """Raised when Promin initialization or activation integrity fails."""


_PORTABLE_CONTROL_MAX_BYTES = 2 * 1024 * 1024


def current_host_binding() -> dict[str, Any]:
    """Return the rebuildable identity of the host running promin.

    This record is deliberately outside canonical project truth.  It lets
    ``doctor`` distinguish a folder move from a project/configuration change
    without committing absolute executable paths or caches.
    """

    executable = resolve_identity_path(sys.executable, strict=True)
    identity = {
        "record_type": "HostBinding",
        "system": {"windows": "windows", "darwin": "darwin", "linux": "linux"}.get(
            platform.system().casefold(), "other"
        ),
        "release": platform.release(),
        "machine": platform.machine().casefold(),
        "python": platform.python_version(),
        "python_executable_digest": digest_file(executable),
        "path_separator": os.sep,
        "case_sensitive_default": os.name != "nt",
        "canonical": False,
        "rebuildable": True,
    }
    return {**identity, "host_binding_digest": digest_value(identity)}


def write_current_host_binding(control_root: Path) -> dict[str, Any]:
    """Atomically publish derived host identity below one control root."""

    record = current_host_binding()
    atomic_write_json(control_root / "host" / "host.json", record, mode=0o600)
    return record


@dataclass
class _ProjectInitLockEntry:
    """Bounded process-local serialization for one project root.

    Atomic rename remains the cross-process correctness boundary.  This lock
    prevents several threads in the same long-lived agent host from repeating
    the full provider/materialization preflight for the same project before one
    of them publishes `.promin`.
    """

    lock: threading.RLock = field(default_factory=threading.RLock)
    users: int = 0


_PROJECT_INIT_LOCKS_GUARD = threading.Lock()
_PROJECT_INIT_LOCKS: dict[str, _ProjectInitLockEntry] = {}


@contextmanager
def _project_init_lock(project_root: Path):
    key = os.path.normcase(str(project_root))
    with _PROJECT_INIT_LOCKS_GUARD:
        entry = _PROJECT_INIT_LOCKS.get(key)
        if entry is None:
            entry = _ProjectInitLockEntry()
            _PROJECT_INIT_LOCKS[key] = entry
        entry.users += 1
    entry.lock.acquire()
    try:
        yield
    finally:
        entry.lock.release()
        with _PROJECT_INIT_LOCKS_GUARD:
            entry.users -= 1
            if entry.users == 0 and _PROJECT_INIT_LOCKS.get(key) is entry:
                del _PROJECT_INIT_LOCKS[key]


def _is_portable_control_shell(control: Path) -> bool:
    """Return true only for the bounded Git-committed `.promin` shell.

    A clone may contain `.promin/portable/**` and `.promin/.gitignore` before
    host-local initialization.  Treating that shell as an initialized control
    plane would make rehydration impossible.
    """

    if control.is_symlink() or not control.is_dir():
        return False
    entries = {item.name for item in control.iterdir()}
    if not entries <= {"portable", ".gitignore"}:
        return False
    total = 0
    seen: set[str] = set()
    ignore = control / ".gitignore"
    if ignore.exists():
        if ignore.is_symlink() or not ignore.is_file():
            return False
        total += ignore.stat().st_size
    portable = control / "portable"
    if portable.exists():
        if portable.is_symlink() or not portable.is_dir():
            return False
        for item in sorted(portable.rglob("*"), key=lambda value: value.as_posix().casefold()):
            relative = item.relative_to(portable).as_posix()
            folded = relative.casefold()
            if folded in seen:
                return False
            seen.add(folded)
            if item.is_symlink():
                return False
            if item.is_dir():
                continue
            if not item.is_file():
                return False
            total += item.stat().st_size
            if total > _PORTABLE_CONTROL_MAX_BYTES:
                return False
    return total <= _PORTABLE_CONTROL_MAX_BYTES


def _merge_portable_control_shell(source: Path, target: Path) -> None:
    if not _is_portable_control_shell(source):
        raise InitError("portable Promin control shell is malformed")
    ignore = source / ".gitignore"
    if ignore.is_file():
        shutil.copy2(ignore, target / ".gitignore")
    portable = source / "portable"
    if portable.is_dir():
        shutil.copytree(portable, target / "portable", dirs_exist_ok=True)


def _parse_provider_timestamp(value: Any) -> datetime:
    """Use the shared Core timestamp parser and expose an init-domain failure."""

    try:
        return parse_utc_second(value)
    except CanonicalError as exc:
        raise InitError("provider invocation timestamp is invalid") from exc


ProviderVerifier = Callable[[Mapping[str, Any], Path], str]
SignatureVerifier = Callable[[Mapping[str, Any], Mapping[str, Any]], bool]


_CONTINUATION_SECRET_BYTES = 32
_PROVIDER_TIMEOUT_MIN_MS = 100
_PROVIDER_TIMEOUT_CEILING_MS = 60_000
_SIGNATURE_PROVIDER_STARTUP_FLOOR_MS = 5_000
_SIGNATURE_PROVIDER_WINDOWS_STARTUP_FLOOR_MS = 10_000
_IMPLEMENTED_PROVIDER_ADAPTERS = frozenset(
    {
        "python-runtime-v1",
        "python-module-signature-v1",
        "executable-signature-v1",
        "git-executable-v1",
        "executable-export-scan-v1",
        "executable-build-dependency-v1",
    }
)
_PROVIDER_FULL_OUTPUT_FIELDS = (
    "output_digest",
    "output_size_bytes",
    "output_size_ceiling_bytes",
)
_PROVIDER_DIAGNOSTIC_CAPTURE_FIELDS = (
    "stdout_capture_digest",
    "stdout_capture_size_bytes",
    "stdout_capture_truncated",
    "stderr_capture_digest",
    "stderr_capture_size_bytes",
    "stderr_capture_truncated",
)


@dataclass(frozen=True)
class ProviderEvidenceLimits:
    diagnostic_capture_bytes_max: int
    full_output_bytes_hard_max: int


def _provider_evidence_limits(bundle: ContractBundle) -> ProviderEvidenceLimits:
    """Compile provider evidence limits from the verified Core semantic owner."""

    model = bundle.core.get("semantic-model.json")
    design_rules = model.get("design_rules") if isinstance(model, Mapping) else None
    owner = (
        design_rules.get("provider_invocation_evidence")
        if isinstance(design_rules, Mapping)
        else None
    )
    required = {
        "diagnostic_capture_bytes_max",
        "diagnostic_capture_fields",
        "full_output_bytes_hard_max",
        "full_output_fields",
        "full_output_rule",
        "immutable_tree_stream_rule",
        "invocation_receipt_digest_rule",
        "invocation_request_digest_rule",
        "selected_ceiling_rule",
    }
    if (
        not isinstance(owner, Mapping)
        or set(owner) != required
        or tuple(owner.get("full_output_fields", ())) != _PROVIDER_FULL_OUTPUT_FIELDS
        or tuple(owner.get("diagnostic_capture_fields", ()))
        != _PROVIDER_DIAGNOSTIC_CAPTURE_FIELDS
        or any(
            not isinstance(owner.get(field), str) or not owner[field]
            for field in (
                "full_output_rule",
                "immutable_tree_stream_rule",
                "invocation_receipt_digest_rule",
                "invocation_request_digest_rule",
                "selected_ceiling_rule",
            )
        )
    ):
        raise InitError("Core provider invocation evidence owner is incomplete")
    capture_max = owner.get("diagnostic_capture_bytes_max")
    output_hard_max = owner.get("full_output_bytes_hard_max")
    if (
        not isinstance(capture_max, int)
        or isinstance(capture_max, bool)
        or capture_max < 1
        or not isinstance(output_hard_max, int)
        or isinstance(output_hard_max, bool)
        or output_hard_max < capture_max
    ):
        raise InitError("Core provider invocation evidence ceilings are invalid")
    return ProviderEvidenceLimits(
        diagnostic_capture_bytes_max=capture_max,
        full_output_bytes_hard_max=output_hard_max,
    )


def _provider_timeout_seconds(binding: Mapping[str, Any]) -> float:
    """Resolve a finite provider timeout without weakening non-signature limits."""

    healthcheck = binding.get("healthcheck")
    if not isinstance(healthcheck, Mapping):
        raise InitError(f"provider healthcheck is invalid: {binding.get('provider_id')}")
    declared_ms = healthcheck.get("timeout_ms")
    if (
        isinstance(declared_ms, bool)
        or not isinstance(declared_ms, int)
        or not _PROVIDER_TIMEOUT_MIN_MS
        <= declared_ms
        <= _PROVIDER_TIMEOUT_CEILING_MS
    ):
        raise InitError(
            f"provider timeout is outside the bounded range: {binding.get('provider_id')}"
        )

    effective_ms = declared_ms
    if binding.get("capability_id") == "signature":
        startup_floor_ms = (
            _SIGNATURE_PROVIDER_WINDOWS_STARTUP_FLOOR_MS
            if os.name == "nt"
            else _SIGNATURE_PROVIDER_STARTUP_FLOOR_MS
        )
        effective_ms = max(declared_ms, startup_floor_ms)
    return min(effective_ms, _PROVIDER_TIMEOUT_CEILING_MS) / 1000


def _init_identity_path(
    value: str,
    project_root: Path,
    *,
    strict: bool = True,
) -> Path:
    """Normalize a provider path through the single platform path owner.

    ``strict=False`` is reserved for comparing immutable receipt metadata after
    the mutable source has disappeared. Any operation that reads, executes, or
    materializes bytes keeps the default strict behaviour.
    """

    try:
        return resolve_identity_path(
            value,
            base=project_root,
            strict=strict,
        )
    except PlatformPathError as exc:
        raise InitError("provider path is unavailable") from exc


def _spawn_provider_argv(
    binding: Mapping[str, Any], argv: Sequence[str], project_root: Path
) -> list[str]:
    """Resolve provider path arguments at the process-spawn boundary.

    The Windows extended-length prefix is deliberately NOT applied here. Python
    passes this list as ``lpCommandLine``, and ``\\\\?\\`` is only honoured by the
    file APIs and by ``lpApplicationName`` -- inside a command line Windows
    rejects it with ERROR_FILENAME_EXCED_RANGE (206). Over-long executables are
    handled by ``_spawn_provider_executable`` below, which feeds
    ``subprocess(executable=...)`` i.e. ``lpApplicationName``.
    """

    result = list(argv)
    if not result:
        return result
    path_indices = (0, 1) if binding.get("invocation", {}).get("kind") == "python-module" else (0,)
    for index in path_indices:
        if index >= len(result):
            raise InitError(f"provider invocation lacks required path argument: {binding.get('provider_id')}")
        result[index] = str(_init_identity_path(str(result[index]), project_root))
    return result


def _spawn_provider_executable(argv: Sequence[str]) -> str | None:
    """Return the ``lpApplicationName`` spelling for a provider spawn.

    ``lpApplicationName`` is the only process-creation parameter that accepts the
    Windows extended-length prefix, so this is where a receipt path beyond
    MAX_PATH has to be carried. Returns None when there is nothing to spawn.
    """

    if not argv:
        return None
    return subprocess_path(argv[0])


def _run_identity_process(
    argv: Sequence[str], **kwargs: Any
) -> subprocess.CompletedProcess[bytes]:
    """Run one executable identity with transport spelling kept out of argv."""

    spawn_argv = [str(value) for value in argv]
    if not spawn_argv:
        raise InitError("provider invocation argv is empty")
    return subprocess.run(
        spawn_argv,
        executable=_spawn_provider_executable(spawn_argv),
        **kwargs,
    )


def _run_provider_process(
    binding: Mapping[str, Any],
    argv: Sequence[str],
    project_root: Path,
    **kwargs: Any,
) -> subprocess.CompletedProcess[bytes]:
    """Normalize provider identities once, then invoke through one spawn owner."""

    return _run_identity_process(
        _spawn_provider_argv(binding, argv, project_root),
        **kwargs,
    )


@dataclass(frozen=True)
class ProviderAdapter:
    capability_id: str
    provider_id: str
    invocation_kind: str
    identity_kind: str
    identity_digest: str
    adapter_id: str
    persistence_scope: str
    reconstructable: bool
    protocol_id: str
    supported_operations: tuple[str, ...]
    operation_contract_digest: str
    operation_contract_digests: Mapping[str, str]
    dependency_receipt_digest: str

    def invocation_evidence(self, operation: str) -> dict[str, Any]:
        if operation not in self.supported_operations:
            raise InitError(
                f"provider operation is not declared by Core: {self.capability_id}: {operation}"
            )
        return {
            "capability_id": self.capability_id,
            "provider_id": self.provider_id,
            "invocation_kind": self.invocation_kind,
            "identity_kind": self.identity_kind,
            "identity_digest": self.identity_digest,
            "adapter_id": self.adapter_id,
            "protocol_id": self.protocol_id,
            "operation": operation,
            "operation_contract_digest": self.operation_contract_digests[operation],
            "dependency_receipt_digest": self.dependency_receipt_digest,
        }

    def binding_evidence(self) -> dict[str, Any]:
        return self.invocation_evidence("provider-binding")

class ProviderDispatch:
    """Resolved implementations for the explicit TechnologiesInit bindings."""

    def __init__(
        self,
        bindings: Mapping[str, Mapping[str, Any]],
        adapters: Mapping[str, ProviderAdapter],
        protocols: Mapping[str, "ProviderProtocol"],
        project_root: Path,
        signature_verifier: SignatureVerifier | None,
        evidence_limits: ProviderEvidenceLimits,
    ) -> None:
        self._bindings = dict(bindings)
        self._adapters = dict(adapters)
        self._protocols = dict(protocols)
        self._project_root = project_root
        self._signature_verifier = signature_verifier
        self._evidence_limits = evidence_limits
        self._health_observations: dict[str, dict[str, Any]] = {}
        self._verified_tree_objects: set[str] = set()

    @property
    def full_output_bytes_hard_max(self) -> int:
        """Return the verified Core hard limit available for pre-invocation selection."""

        return self._evidence_limits.full_output_bytes_hard_max

    @property
    def diagnostic_capture_bytes_max(self) -> int:
        """Return the verified Core bound for each diagnostic stream capture."""

        return self._evidence_limits.diagnostic_capture_bytes_max

    def binding(self, capability_id: str) -> Mapping[str, Any]:
        binding = self._bindings.get(capability_id)
        if binding is None:
            raise InitError(f"provider capability is not configured: {capability_id}")
        return binding

    def adapter(self, capability_id: str) -> ProviderAdapter:
        adapter = self._adapters.get(capability_id)
        if adapter is None:
            raise InitError(f"provider capability is not configured: {capability_id}")
        return adapter

    def signature_verifier(self) -> SignatureVerifier:
        self.binding("signature")
        if self._signature_verifier is None:
            raise InitError("configured signature provider has no usable adapter")
        return self._signature_verifier

    def binding_evidence(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            self._operation_identity_evidence(capability, "provider-binding")
            for capability in sorted(self._adapters)
        )

    def validate_invocation_evidence(
        self, value: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Validate one immutable invocation receipt against active bindings.

        The receipt is observational evidence, not authority.  Validation binds
        its static provider identity to the exact configured implementation and
        verifies that the claimed receipt digest covers the same canonical fields.
        """

        if not isinstance(value, Mapping):
            raise InitError("provider invocation evidence must be an object")
        capability_id = value.get("capability_id")
        operation = value.get("operation")
        if not isinstance(capability_id, str) or not isinstance(operation, str):
            raise InitError("provider invocation evidence lacks capability or operation")
        expected = self._operation_identity_evidence(capability_id, operation)
        if any(value.get(field) != expected_value for field, expected_value in expected.items()):
            raise InitError("provider invocation evidence differs from active binding")
        receipt_digest = value.get("invocation_receipt_digest")
        if not isinstance(receipt_digest, str) or re.fullmatch(r"[0-9a-f]{64}", receipt_digest) is None:
            raise InitError("provider invocation receipt digest is invalid")
        receipt_body = dict(value)
        receipt_body.pop("invocation_receipt_digest", None)
        if digest_value(receipt_body) != receipt_digest:
            raise InitError("provider invocation receipt digest differs from its fields")
        return deepcopy(dict(value))

    def evidence(self) -> tuple[dict[str, Any], ...]:
        return self.binding_evidence()

    def runtime_evidence(self) -> tuple[dict[str, Any], ...]:
        missing = set(self._adapters).difference(self._health_observations)
        if missing:
            raise InitError(
                "provider health evidence requires executed preflight: "
                + ", ".join(sorted(missing))
            )
        return tuple(
            deepcopy(self._health_observations[capability])
            for capability in sorted(self._adapters)
        )

    def _record_health_observation(
        self, capability_id: str, observation: Mapping[str, Any]
    ) -> None:
        adapter = self.adapter(capability_id)
        binding = self.binding(capability_id)
        required = {
            "capability_id",
            "provider_id",
            "invocation_kind",
            "identity_kind",
            "identity_digest",
            "adapter_id",
            "protocol_id",
            "operation",
            "operation_contract_digest",
            "invocation_receipt_digest",
            "dependency_receipt_digest",
            "persistence_scope",
            "reconstructable",
            "invoked",
            "started_at",
            "completed_at",
            "outcome",
            "exit_code",
            "stdout_digest",
            "stdout_size_bytes",
            "stderr_digest",
            "stderr_size_bytes",
            "authoritative",
            "pass_credit",
        }
        expected_identity = adapter.invocation_evidence("healthcheck")
        started_at = observation.get("started_at")
        completed_at = observation.get("completed_at")
        started_instant = _parse_provider_timestamp(started_at)
        completed_instant = _parse_provider_timestamp(completed_at)
        digest_fields = (
            "identity_digest",
            "operation_contract_digest",
            "invocation_receipt_digest",
            "dependency_receipt_digest",
            "stdout_digest",
            "stderr_digest",
        )
        if (
            set(observation) != required
            or any(observation.get(key) != value for key, value in expected_identity.items())
            or observation.get("persistence_scope") != adapter.persistence_scope
            or observation.get("reconstructable") is not True
            or observation.get("invoked") is not True
            or observation.get("outcome") not in {"healthy", "degraded", "failed"}
            or observation.get("outcome") != "healthy"
            or observation.get("exit_code") != binding["healthcheck"]["expected_exit"]
            or isinstance(observation.get("exit_code"), bool)
            or any(
                not isinstance(observation.get(field), str)
                or re.fullmatch(r"[0-9a-f]{64}", str(observation[field])) is None
                for field in digest_fields
            )
            or started_instant > completed_instant
            or any(
                not isinstance(observation.get(field), int)
                or isinstance(observation.get(field), bool)
                or not 0 <= int(observation[field]) <= 1024 * 1024
                for field in ("stdout_size_bytes", "stderr_size_bytes")
            )
            or observation.get("authoritative") is not False
            or observation.get("pass_credit") is not False
        ):
            raise InitError(f"provider health observation is invalid: {capability_id}")
        self._health_observations[capability_id] = deepcopy(dict(observation))

    def technologies(self) -> dict[str, Any]:
        """Return the verified runtime bindings, including immutable receipt paths."""

        return {
            "record_type": "TechnologiesInit",
            "bindings": [
                deepcopy(self._bindings[capability])
                for capability in sorted(self._bindings)
            ],
        }

    def _operation_identity_evidence(
        self, capability_id: str, operation: str
    ) -> dict[str, Any]:
        binding = self.binding(capability_id)
        closure = binding.get("implementation_closure")
        closure_digest = (
            closure.get("closure_digest") if isinstance(closure, Mapping) else None
        )
        if (
            not isinstance(closure_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", closure_digest) is None
        ):
            raise InitError(
                f"provider operation lacks its implementation closure: {capability_id}"
            )
        return {
            **self.adapter(capability_id).invocation_evidence(operation),
            "implementation_closure_digest": closure_digest,
        }

    def _select_output_size_ceiling(
        self, operation: str, selected: int | None
    ) -> int:
        if operation == "immutable-tree-object" and selected is None:
            selected = 65
        if selected is None:
            raise InitError("provider output size ceiling must be selected before invocation")
        if (
            not isinstance(selected, int)
            or isinstance(selected, bool)
            or not 1 <= selected <= self._evidence_limits.full_output_bytes_hard_max
        ):
            raise InitError("provider output size ceiling exceeds the Core hard limit")
        if operation == "immutable-tree-object" and selected != 65:
            raise InitError("tree object response ceiling must be exactly 65 bytes")
        if (
            operation != "immutable-tree-stream"
            and selected > self._evidence_limits.diagnostic_capture_bytes_max
        ):
            raise InitError("buffered provider output exceeds the Core capture limit")
        return selected

    def prepare_invocation(
        self,
        capability_id: str,
        operation: str,
        request: Mapping[str, Any],
        *,
        output_size_ceiling_bytes: int | None = None,
    ) -> "ProviderInvocationPlan":
        adapter = self.adapter(capability_id)
        protocol = self._protocols[capability_id]
        if operation not in protocol.operation_contracts:
            raise InitError(
                f"provider operation is not declared by Core: {capability_id}: {operation}"
            )
        binding = self.binding(capability_id)
        selected_output_ceiling = self._select_output_size_ceiling(
            operation, output_size_ceiling_bytes
        )
        executable = _init_identity_path(
            str(binding["invocation"]["value"]), self._project_root
        )
        evidence = self._operation_identity_evidence(capability_id, operation)
        if adapter.adapter_id == "git-executable-v1":
            if request.get("repository") != str(self._project_root) or set(request) not in (
                {"repository"},
                {"repository", "tree_object"},
            ):
                raise InitError("filesystem inventory request is not bound to the project root")
            if operation == "immutable-tree-object" and set(request) == {"repository"}:
                argv = (str(executable), "rev-parse", "--verify", "HEAD^{tree}")
                response_kind = "lowercase-object-id-lf"
            elif operation == "immutable-tree-stream" and set(request) == {
                "repository",
                "tree_object",
            }:
                tree_object = request["tree_object"]
                if not isinstance(tree_object, str) or not re.fullmatch(
                    r"(?:[0-9a-f]{40}|[0-9a-f]{64})", tree_object
                ):
                    raise InitError("filesystem inventory tree object is invalid")
                if tree_object not in self._verified_tree_objects:
                    raise InitError(
                        "filesystem inventory tree object lacks an executed verification"
                    )
                argv = (str(executable), "archive", "--format=tar", tree_object)
                response_kind = "raw-git-tar-stream"
            else:
                raise InitError("filesystem inventory operation/request mismatch")
            return self._seal_invocation_plan(
                ProviderInvocationPlan(
                    capability_id=capability_id,
                    protocol_id=protocol.protocol_id,
                    operation=operation,
                    argv=argv,
                    cwd=self._project_root,
                    stdin=None,
                    response_kind=response_kind,
                    evidence=evidence,
                    output_size_ceiling_bytes=selected_output_ceiling,
                    invocation_request_digest="",
                    env=_git_receipt_environment(binding),
                )
            )
        if adapter.adapter_id in {
            "executable-export-scan-v1",
            "executable-build-dependency-v1",
        }:
            if request.get("operation") != operation:
                raise InitError("canonical JSON provider request operation mismatch")
            return self._seal_invocation_plan(
                ProviderInvocationPlan(
                    capability_id=capability_id,
                    protocol_id=protocol.protocol_id,
                    operation=operation,
                    argv=(
                        str(executable),
                        "--promin-provider-v1",
                        protocol.protocol_id,
                        operation,
                    ),
                    cwd=self._project_root,
                    stdin=canonical_bytes(dict(request)),
                    response_kind="canonical-json",
                    evidence=evidence,
                    output_size_ceiling_bytes=selected_output_ceiling,
                    invocation_request_digest="",
                    env=None,
                )
            )
        raise InitError(
            f"provider operation requires its domain runtime hook: {capability_id}: {operation}"
        )

    def _invocation_request_receipt_unchecked(
        self, plan: "ProviderInvocationPlan"
    ) -> dict[str, Any]:
        expected = self._operation_identity_evidence(plan.capability_id, plan.operation)
        environment_allowlist = (
            {"GIT_EXEC_PATH": plan.env["GIT_EXEC_PATH"]}
            if plan.env is not None and "GIT_EXEC_PATH" in plan.env
            else {}
        )
        return {
            "record_type": "ProviderInvocationRequestReceipt",
            "protocol_id": plan.protocol_id,
            "operation": plan.operation,
            "argv_or_module_call": {"kind": "argv", "argv": list(plan.argv)},
            "configured_cwd": str(plan.cwd),
            "stdin_digest": hashlib.sha256(plan.stdin or b"").hexdigest(),
            "response_kind": plan.response_kind,
            "output_size_ceiling_bytes": plan.output_size_ceiling_bytes,
            "environment_allowlist": environment_allowlist,
            "provider_identity_digest": expected["identity_digest"],
            "dependency_receipt_digest": expected["dependency_receipt_digest"],
            "implementation_closure_digest": expected[
                "implementation_closure_digest"
            ],
        }

    def _seal_invocation_plan(
        self, plan: "ProviderInvocationPlan"
    ) -> "ProviderInvocationPlan":
        receipt = self._invocation_request_receipt_unchecked(plan)
        return replace(plan, invocation_request_digest=digest_value(receipt))

    def _validate_invocation_plan(self, plan: "ProviderInvocationPlan") -> None:
        adapter = self.adapter(plan.capability_id)
        binding = self.binding(plan.capability_id)
        executable = str(
            _init_identity_path(str(binding["invocation"]["value"]), self._project_root)
        )
        if (
            plan.protocol_id != adapter.protocol_id
            or plan.cwd != self._project_root
            or self._select_output_size_ceiling(
                plan.operation, plan.output_size_ceiling_bytes
            )
            != plan.output_size_ceiling_bytes
            or plan.invocation_request_digest
            != digest_value(self._invocation_request_receipt_unchecked(plan))
            or dict(plan.evidence)
            != self._operation_identity_evidence(plan.capability_id, plan.operation)
        ):
            raise InitError("provider invocation plan identity is stale")
        if adapter.adapter_id == "git-executable-v1":
            expected_environment = _git_receipt_environment(binding)
            environment_matches = (
                plan.env is not None
                and plan.env.get("GIT_EXEC_PATH")
                == expected_environment.get("GIT_EXEC_PATH")
            )
            valid = (
                plan.operation == "immutable-tree-object"
                and plan.argv
                == (executable, "rev-parse", "--verify", "HEAD^{tree}")
                and plan.stdin is None
                and plan.response_kind == "lowercase-object-id-lf"
                and environment_matches
            ) or (
                plan.operation == "immutable-tree-stream"
                and len(plan.argv) == 4
                and plan.argv[:3] == (executable, "archive", "--format=tar")
                and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", plan.argv[3])
                is not None
                and plan.argv[3] in self._verified_tree_objects
                and plan.stdin is None
                and plan.response_kind == "raw-git-tar-stream"
                and environment_matches
            )
            if not valid:
                raise InitError("Git provider invocation plan differs from Core")
            return
        if adapter.adapter_id in {
            "executable-export-scan-v1",
            "executable-build-dependency-v1",
        }:
            request = parse_json_strict(plan.stdin or b"")
            if (
                plan.argv
                != (
                    executable,
                    "--promin-provider-v1",
                    plan.protocol_id,
                    plan.operation,
                )
                or not isinstance(request, Mapping)
                or request.get("operation") != plan.operation
                or canonical_bytes(request) != plan.stdin
                or plan.response_kind != "canonical-json"
                or plan.env is not None
            ):
                raise InitError("canonical JSON provider invocation plan differs from Core")
            return
        raise InitError("provider adapter has no external operation completion hook")

    def invocation_request_receipt(
        self, plan: "ProviderInvocationPlan"
    ) -> dict[str, Any]:
        """Return the canonical request owner selected before provider execution."""

        self._validate_invocation_plan(plan)
        return self._invocation_request_receipt_unchecked(plan)

    def complete_invocation_evidence(
        self,
        plan: "ProviderInvocationPlan",
        *,
        started_at: str,
        completed_at: str,
        outcome: str,
        exit_code: int | None,
        output_digest: str,
        output_size_bytes: int,
        stdout_capture_digest: str,
        stdout_capture_size_bytes: int,
        stdout_capture_truncated: bool,
        stderr_capture_digest: str,
        stderr_capture_size_bytes: int,
        stderr_capture_truncated: bool,
    ) -> dict[str, Any]:
        self._validate_invocation_plan(plan)
        expected = self._operation_identity_evidence(plan.capability_id, plan.operation)
        if outcome not in {"success", "failure", "blocked"}:
            raise InitError("provider invocation outcome is invalid")
        if (
            (
                exit_code is not None
                and (not isinstance(exit_code, int) or isinstance(exit_code, bool))
            )
            or (outcome == "success" and exit_code != 0)
            or (outcome == "failure" and exit_code is None)
            or (outcome == "blocked" and exit_code is not None)
        ):
            raise InitError("provider invocation outcome and exit code disagree")
        started = _parse_provider_timestamp(started_at)
        completed = _parse_provider_timestamp(completed_at)
        if started > completed:
            raise InitError("provider invocation timestamps are invalid")
        for value in (
            output_digest,
            stdout_capture_digest,
            stderr_capture_digest,
        ):
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise InitError("provider invocation digest is invalid")
        if (
            not isinstance(output_size_bytes, int)
            or isinstance(output_size_bytes, bool)
            or not 0 <= output_size_bytes <= plan.output_size_ceiling_bytes
        ):
            raise InitError("provider full output exceeds its selected ceiling")
        capture_max = self._evidence_limits.diagnostic_capture_bytes_max
        if any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= capture_max
            for value in (
                stdout_capture_size_bytes,
                stderr_capture_size_bytes,
            )
        ) or any(
            not isinstance(value, bool)
            for value in (stdout_capture_truncated, stderr_capture_truncated)
        ):
            raise InitError("provider invocation captured stream size is invalid")
        if stdout_capture_truncated:
            if stdout_capture_size_bytes >= output_size_bytes:
                raise InitError("truncated stdout capture does not omit output bytes")
        elif (
            stdout_capture_size_bytes != output_size_bytes
            or stdout_capture_digest != output_digest
        ):
            raise InitError("complete stdout capture differs from full output")
        input_digest = hashlib.sha256(plan.stdin or b"").hexdigest()
        request_receipt = self.invocation_request_receipt(plan)
        if digest_value(request_receipt) != plan.invocation_request_digest:
            raise InitError("provider invocation request receipt changed after selection")
        evidence = {
            **expected,
            "invoked": True,
            "started_at": started_at,
            "completed_at": completed_at,
            "outcome": outcome,
            "exit_code": exit_code,
            "input_digest": input_digest,
            "invocation_request_digest": plan.invocation_request_digest,
            "output_digest": output_digest,
            "output_size_bytes": output_size_bytes,
            "output_size_ceiling_bytes": plan.output_size_ceiling_bytes,
            "stdout_capture_digest": stdout_capture_digest,
            "stdout_capture_size_bytes": stdout_capture_size_bytes,
            "stdout_capture_truncated": stdout_capture_truncated,
            "stderr_capture_digest": stderr_capture_digest,
            "stderr_capture_size_bytes": stderr_capture_size_bytes,
            "stderr_capture_truncated": stderr_capture_truncated,
            "authoritative": False,
            "pass_credit": False,
        }
        return {**evidence, "invocation_receipt_digest": digest_value(evidence)}

    def complete_streamed_invocation_evidence(
        self,
        plan: "ProviderInvocationPlan",
        *,
        started_at: str,
        completed_at: str,
        outcome: str,
        exit_code: int | None,
        output_digest: str,
        output_size_bytes: int,
        stdout_capture_digest: str,
        stdout_capture_size_bytes: int,
        stdout_capture_truncated: bool,
        stderr_capture_digest: str,
        stderr_capture_size_bytes: int,
        stderr_capture_truncated: bool,
    ) -> dict[str, Any]:
        if (
            plan.capability_id != "filesystem-inventory"
            or plan.operation != "immutable-tree-stream"
            or plan.response_kind != "raw-git-tar-stream"
        ):
            raise InitError("stream completion requires the Core immutable tree stream")
        return self.complete_invocation_evidence(
            plan,
            started_at=started_at,
            completed_at=completed_at,
            outcome=outcome,
            exit_code=exit_code,
            output_digest=output_digest,
            output_size_bytes=output_size_bytes,
            stdout_capture_digest=stdout_capture_digest,
            stdout_capture_size_bytes=stdout_capture_size_bytes,
            stdout_capture_truncated=stdout_capture_truncated,
            stderr_capture_digest=stderr_capture_digest,
            stderr_capture_size_bytes=stderr_capture_size_bytes,
            stderr_capture_truncated=stderr_capture_truncated,
        )

    def complete_buffered_invocation_evidence(
        self,
        plan: "ProviderInvocationPlan",
        *,
        started_at: str,
        completed_at: str,
        outcome: str,
        exit_code: int | None,
        stdout: bytes,
        stderr: bytes,
    ) -> dict[str, Any]:
        capture_max = self._evidence_limits.diagnostic_capture_bytes_max
        if (
            len(stdout) > plan.output_size_ceiling_bytes
            or len(stdout) > capture_max
            or len(stderr) > capture_max
        ):
            raise InitError("provider invocation output exceeds its evidence bound")
        stdout_digest = hashlib.sha256(stdout).hexdigest()
        return self.complete_invocation_evidence(
            plan,
            started_at=started_at,
            completed_at=completed_at,
            outcome=outcome,
            exit_code=exit_code,
            output_digest=stdout_digest,
            output_size_bytes=len(stdout),
            stdout_capture_digest=stdout_digest,
            stdout_capture_size_bytes=len(stdout),
            stdout_capture_truncated=False,
            stderr_capture_digest=hashlib.sha256(stderr).hexdigest(),
            stderr_capture_size_bytes=len(stderr),
            stderr_capture_truncated=False,
        )

    def invoke_canonical_json(
        self,
        capability_id: str,
        operation: str,
        request: Mapping[str, Any],
        *,
        max_output_bytes: int = 1024 * 1024,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if (
            not isinstance(max_output_bytes, int)
            or isinstance(max_output_bytes, bool)
            or not 1
            <= max_output_bytes
            <= self._evidence_limits.diagnostic_capture_bytes_max
        ):
            raise InitError("provider response bound is outside the Core evidence ceiling")
        plan = self.prepare_invocation(
            capability_id,
            operation,
            request,
            output_size_ceiling_bytes=max_output_bytes,
        )
        if plan.response_kind != "canonical-json" or plan.stdin is None:
            raise InitError("provider operation is not a canonical JSON IPC protocol")
        timeout = _provider_timeout_seconds(self.binding(capability_id))
        started_at = _utc_second_text()
        try:
            completed = _run_provider_process(
                self.binding(capability_id),
                plan.argv,
                self._project_root,
                cwd=plan.cwd,
                input=plan.stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
                shell=False,
                env=plan.env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise InitError(f"provider invocation unavailable: {capability_id}: {exc}") from exc
        completed_at = _utc_second_text()
        if completed.returncode != 0:
            raise InitError(
                f"provider invocation failed: {capability_id}: exit={completed.returncode}"
            )
        if len(completed.stdout) > max_output_bytes or len(completed.stderr) > 64 * 1024:
            raise InitError(f"provider response exceeds its bounded protocol: {capability_id}")
        response = parse_json_strict(completed.stdout)
        if not isinstance(response, dict) or canonical_bytes(response) != completed.stdout:
            raise InitError(f"provider response is not canonical JSON: {capability_id}")
        evidence = self.complete_buffered_invocation_evidence(
            plan,
            started_at=started_at,
            completed_at=completed_at,
            outcome="success",
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        return response, evidence

    def validate_tree_object_response(
        self,
        plan: "ProviderInvocationPlan",
        *,
        returncode: int,
        stdout: bytes,
        stderr: bytes,
    ) -> str:
        if (
            plan.capability_id != "filesystem-inventory"
            or plan.operation != "immutable-tree-object"
            or plan.response_kind != "lowercase-object-id-lf"
        ):
            raise InitError("tree object response does not match its prepared invocation")
        if returncode != 0 or len(stderr) > 64 * 1024:
            raise InitError("filesystem inventory tree object operation failed")
        if not re.fullmatch(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})\n", stdout):
            raise InitError("filesystem inventory returned an invalid tree object response")
        return stdout[:-1].decode("ascii")

    def invoke_tree_object(
        self, request: Mapping[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        plan = self.prepare_invocation(
            "filesystem-inventory", "immutable-tree-object", request
        )
        started_at = _utc_second_text()
        try:
            completed = _run_provider_process(
                self.binding("filesystem-inventory"),
                plan.argv,
                self._project_root,
                cwd=plan.cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=_provider_timeout_seconds(
                    self.binding("filesystem-inventory")
                ),
                check=False,
                shell=False,
                env=plan.env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise InitError(f"filesystem inventory provider unavailable: {exc}") from exc
        completed_at = _utc_second_text()
        tree_object = self.validate_tree_object_response(
            plan,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        self._verified_tree_objects.add(tree_object)
        evidence = self.complete_buffered_invocation_evidence(
            plan,
            started_at=started_at,
            completed_at=completed_at,
            outcome="success",
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        return tree_object, evidence


@dataclass(frozen=True)
class ProviderInvocationPlan:
    capability_id: str
    protocol_id: str
    operation: str
    argv: tuple[str, ...]
    cwd: Path
    stdin: bytes | None
    response_kind: str
    evidence: Mapping[str, Any]
    output_size_ceiling_bytes: int
    invocation_request_digest: str
    env: Mapping[str, str] | None = None


@dataclass(frozen=True)
class ProviderProtocol:
    capability_id: str
    protocol_id: str
    supported_commands: tuple[str, ...]
    supported_bindings: Mapping[tuple[str, str], str]
    receipt_persistence: str
    dependency_receipt_rule: Mapping[str, Any]
    operation_contracts: Mapping[str, Mapping[str, Any]]


_SUPPORTED_DEPENDENCY_RECEIPT_RULE: Mapping[str, Any] = {
    "aggregate_digest_rule": "sha256(canonical receipt without aggregate_digest)",
    "component_fields": [
        "component_id",
        "component_kind",
        "source",
        "version",
        "digest",
        "size_bytes",
    ],
    "component_order": "component-id-ascending",
    "complete": True,
    "os_substrate_excluded": True,
    "provider_owned_scope": "configured-provider-root-and-runtime-components",
    "unresolved_dependencies": "reject",
}


def provider_protocol_table(bundle: ContractBundle) -> Mapping[str, ProviderProtocol]:
    """Compile the only admitted provider vocabulary from the verified Core owner."""

    model = bundle.core.get("semantic-model.json")
    capabilities = model.get("technology_capabilities") if isinstance(model, Mapping) else None
    if not isinstance(capabilities, list) or not capabilities:
        raise InitError("Core provider capability vocabulary is unavailable")
    result: dict[str, ProviderProtocol] = {}
    for item in capabilities:
        if not isinstance(item, Mapping):
            raise InitError("Core provider capability entry is invalid")
        capability_id = item.get("id")
        protocol = item.get("adapter_protocol")
        if not isinstance(capability_id, str) or not capability_id or capability_id in result:
            raise InitError("Core provider capability vocabulary is duplicate or invalid")
        if (
            not isinstance(protocol, Mapping)
            or set(protocol)
            != {
                "protocol_id",
                "receipt_persistence",
                "dependency_receipt_rule",
                "supported_bindings",
                "supported_commands",
                "operation_contracts",
                "unknown_binding",
            }
            or protocol.get("unknown_binding") != "reject"
        ):
            raise InitError(f"Core provider protocol is not fail-closed: {capability_id}")
        protocol_id = protocol.get("protocol_id")
        receipt_persistence = protocol.get("receipt_persistence")
        dependency_receipt_rule = protocol.get("dependency_receipt_rule")
        commands = protocol.get("supported_commands")
        bindings = protocol.get("supported_bindings")
        operation_contracts = protocol.get("operation_contracts")
        if (
            not isinstance(protocol_id, str)
            or not protocol_id
            or receipt_persistence != "content-addressed-receipt"
            or dependency_receipt_rule != _SUPPORTED_DEPENDENCY_RECEIPT_RULE
            or not isinstance(commands, list)
            or not commands
            or any(not isinstance(value, str) or not value for value in commands)
            or len(commands) != len(set(commands))
            or not {"provider-binding", "healthcheck"}.issubset(commands)
            or not isinstance(bindings, list)
            or not bindings
            or not isinstance(operation_contracts, Mapping)
            or set(operation_contracts) != set(commands)
            or any(
                not isinstance(value, Mapping)
                or set(value) != {"request", "response"}
                or any(
                    not isinstance(field, str) or not field
                    for field in value.values()
                )
                for value in operation_contracts.values()
            )
        ):
            raise InitError(f"Core provider protocol is incomplete: {capability_id}")
        supported: dict[tuple[str, str], str] = {}
        for candidate in bindings:
            if not isinstance(candidate, Mapping) or set(candidate) != {
                "adapter_id",
                "identity_kind",
                "invocation_kind",
            }:
                raise InitError(f"Core provider binding protocol is invalid: {capability_id}")
            adapter_id = candidate.get("adapter_id")
            invocation_kind = candidate.get("invocation_kind")
            identity_kind = candidate.get("identity_kind")
            if any(
                not isinstance(value, str) or not value
                for value in (adapter_id, invocation_kind, identity_kind)
            ):
                raise InitError(f"Core provider binding protocol is invalid: {capability_id}")
            key = (str(invocation_kind), str(identity_kind))
            if key in supported:
                raise InitError(f"Core provider binding protocol is ambiguous: {capability_id}")
            supported[key] = str(adapter_id)
        result[capability_id] = ProviderProtocol(
            capability_id=capability_id,
            protocol_id=protocol_id,
            supported_commands=tuple(commands),
            supported_bindings=supported,
            receipt_persistence=receipt_persistence,
            dependency_receipt_rule=deepcopy(dict(dependency_receipt_rule)),
            operation_contracts=deepcopy(dict(operation_contracts)),
        )
    return result


def _canonical_runtime_bundle() -> ContractBundle:
    package = bundle_root()
    preset = package / "presets" / "semantic-morok-tower.json"
    return load_contract_bundle(package, preset)


def _provider_receipt_name(binding: Mapping[str, Any]) -> str:
    source = Path(str(binding["identity"]["source"]))
    suffix = source.suffix.casefold()
    if suffix and (
        len(suffix) > 12
        or suffix[0] != "."
        or not suffix[1:].replace("_", "").isalnum()
    ):
        raise InitError(f"provider source suffix is not canonical: {binding['provider_id']}")
    return "payload" + suffix


def _provider_receipt_path(
    receipt_root: Path, binding: Mapping[str, Any]
) -> Path:
    digest = binding.get("identity", {}).get("digest")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise InitError(f"provider identity digest is invalid: {binding.get('provider_id')}")
    return receipt_root / digest[:24] / _provider_receipt_name(binding)


def _component_receipt_path(
    receipt_root: Path,
    binding: Mapping[str, Any],
    component: Mapping[str, Any],
) -> Path:
    component_id = str(component["component_id"])
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", component_id):
        raise InitError(f"provider dependency component id is invalid: {component_id}")
    return (
        _provider_receipt_path(receipt_root, binding).parent
        / "components"
        / component_id
    )


def _provider_tree_source_file(root: Path, path: Path) -> Path:
    """Return a bounded regular source for a provider-tree path.

    File symlinks are accepted only when their fully resolved target remains
    inside the configured provider tree.  The receipt records the bytes under
    the symlink's relative path and materializes them as an ordinary file.  This
    supports normal Git installations whose helper names are in-tree symlinks
    without committing link semantics or allowing an escape from the provider
    root.  Directory links remain rejected.
    """

    resolved_root = resolve_identity_path(root, strict=True)
    try:
        mode = os.lstat(filesystem_path(path)).st_mode
    except OSError as exc:
        raise InitError(f"provider dependency file is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(mode):
        try:
            target = resolve_identity_path(path, strict=True)
            target.relative_to(resolved_root)
        except (OSError, ValueError) as exc:
            raise InitError(f"provider dependency link escapes its tree: {path}") from exc
        try:
            target_mode = os.stat(filesystem_path(target), follow_symlinks=False).st_mode
        except OSError as exc:
            raise InitError(f"provider dependency link target is unavailable: {path}") from exc
        if not stat.S_ISREG(target_mode) or os.path.islink(filesystem_path(target)):
            raise InitError(f"provider dependency link target is not a regular file: {path}")
        return target
    if not stat.S_ISREG(mode):
        raise InitError(f"provider dependency path is not a regular file: {path}")
    try:
        resolve_identity_path(path, strict=True).relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise InitError(f"provider dependency file escapes its tree: {path}") from exc
    return path


def _provider_tree_files(root: Path) -> tuple[list[dict[str, Any]], int]:
    try:
        resolved = resolve_identity_path(root, strict=True)
    except OSError as exc:
        raise InitError(f"provider dependency tree is unavailable: {root}: {exc}") from exc
    if (
        not os.path.isdir(filesystem_path(resolved))
        or os.path.islink(filesystem_path(resolved))
    ):
        raise InitError(f"provider dependency tree is not a real directory: {root}")
    files: list[dict[str, Any]] = []
    total = 0
    for directory, directories, filenames in os.walk(
        _native_path(resolved), topdown=True, followlinks=False
    ):
        base = resolve_identity_path(directory, strict=True)
        for name in tuple(directories):
            child = base / name
            is_junction = bool(
                getattr(os.path, "isjunction", lambda _value: False)(
                    filesystem_path(child)
                )
            )
            if os.path.islink(filesystem_path(child)) or is_junction:
                raise InitError(f"provider dependency tree contains a link: {child}")
        for name in filenames:
            logical_path = base / name
            source_path = _provider_tree_source_file(resolved, logical_path)
            size = os.stat(filesystem_path(source_path), follow_symlinks=False).st_size
            total += size
            files.append(
                {
                    "path": logical_path.relative_to(resolved).as_posix(),
                    "digest": digest_file(source_path),
                    "size_bytes": size,
                }
            )
            if len(files) > 100_000 or total > 8 * 1024 * 1024 * 1024:
                raise InitError("provider dependency tree exceeds the bounded receipt")
    files.sort(key=lambda item: item["path"].encode("utf-8"))
    if not files:
        raise InitError("provider dependency tree is empty")
    return files, total


def _provider_tree_digest(root: Path) -> tuple[str, int]:
    files, total = _provider_tree_files(root)
    return digest_value({"record_type": "ProviderTreeReceipt", "files": files}), total


def _reject_product_provider_tree_overlap(provider_tree: Path, project_root: Path) -> None:
    tree = resolve_identity_path(provider_tree, strict=True)
    project = resolve_identity_path(project_root, strict=True)
    if tree == project or tree.is_relative_to(project) or project.is_relative_to(tree):
        raise InitError("provider dependency tree must not overlap the product project")


def build_provider_dependency_receipt(
    binding: Mapping[str, Any],
    project_root: Path,
    *,
    provider_tree: Path | None = None,
) -> dict[str, Any]:
    """Build a complete dependency receipt from explicit local component roots."""

    capability_id = str(binding["capability_id"])
    invocation_kind = str(binding["invocation"]["kind"])
    source = _init_identity_path(str(binding["identity"]["source"]), project_root)
    primary_id = (
        "interpreter"
        if invocation_kind == "python-runtime"
        else "git-executable"
        if capability_id == "filesystem-inventory"
        else "provider-module"
        if invocation_kind == "python-module"
        else "provider-executable"
    )
    components: list[dict[str, Any]] = [
        {
            "component_id": primary_id,
            "component_kind": "provider-file",
            "source": str(source),
            "version": str(binding["version"]),
            "digest": digest_file(source),
            "size_bytes": source.stat(follow_symlinks=False).st_size,
        }
    ]
    if invocation_kind == "python-module":
        interpreter = require_regular_file(
            resolve_identity_path(sys.executable, strict=True),
            root=resolve_identity_path(sys.executable, strict=True).parent,
        )
        components.append(
            {
                "component_id": "interpreter",
                "component_kind": "provider-file",
                "source": str(interpreter),
                "version": platform.python_version(),
                "digest": digest_file(interpreter),
                "size_bytes": interpreter.stat(follow_symlinks=False).st_size,
            }
        )
    if capability_id == "shape-validation":
        components.append(_jsonschema_receipt())
    if capability_id == "query-projection":
        components.append(_sqlite_receipt())
    if capability_id == "filesystem-inventory":
        if provider_tree is None:
            raise InitError("Git provider requires an explicit complete provider tree")
        tree = resolve_identity_path(provider_tree, strict=True)
        _reject_product_provider_tree_overlap(tree, project_root)
        tree_digest, tree_size = _provider_tree_digest(tree)
        components.append(
            {
                "component_id": "git-provider-tree",
                "component_kind": "provider-tree",
                "source": str(tree),
                "version": str(binding["version"]),
                "digest": tree_digest,
                "size_bytes": tree_size,
            }
        )
    components.sort(key=lambda item: str(item["component_id"]).encode("utf-8"))
    identity = {
        "complete": _SUPPORTED_DEPENDENCY_RECEIPT_RULE["complete"],
        "provider_owned_scope": _SUPPORTED_DEPENDENCY_RECEIPT_RULE[
            "provider_owned_scope"
        ],
        "os_substrate_excluded": _SUPPORTED_DEPENDENCY_RECEIPT_RULE[
            "os_substrate_excluded"
        ],
        "components": components,
    }
    return {**identity, "aggregate_digest": digest_value(identity)}


def _validate_provider_dependency_receipt_shape(
    binding: Mapping[str, Any], project_root: Path
) -> list[Mapping[str, Any]]:
    receipt = binding.get("dependency_receipt")
    if (
        not isinstance(receipt, Mapping)
        or set(receipt)
        != {
            "complete",
            "provider_owned_scope",
            "os_substrate_excluded",
            "components",
            "aggregate_digest",
        }
        or receipt.get("complete")
        is not _SUPPORTED_DEPENDENCY_RECEIPT_RULE["complete"]
        or receipt.get("provider_owned_scope")
        != _SUPPORTED_DEPENDENCY_RECEIPT_RULE["provider_owned_scope"]
        or receipt.get("os_substrate_excluded")
        is not _SUPPORTED_DEPENDENCY_RECEIPT_RULE["os_substrate_excluded"]
        or not isinstance(receipt.get("components"), list)
        or not receipt["components"]
    ):
        raise InitError(f"provider dependency receipt is incomplete: {binding.get('provider_id')}")
    components = receipt["components"]
    if any(not isinstance(component, Mapping) for component in components):
        raise InitError("provider dependency component shape is invalid")
    if components != sorted(
        components, key=lambda item: str(item.get("component_id", "")).encode("utf-8")
    ):
        raise InitError("provider dependency components are not canonically ordered")
    seen: set[str] = set()
    component_kinds: dict[str, str] = {}
    invocation_kind = str(binding["invocation"]["kind"])
    capability_id = str(binding["capability_id"])
    primary_id = (
        "interpreter"
        if invocation_kind == "python-runtime"
        else "git-executable"
        if capability_id == "filesystem-inventory"
        else "provider-module"
        if invocation_kind == "python-module"
        else "provider-executable"
    )
    primary_source = _init_identity_path(
        str(binding["identity"]["source"]),
        project_root,
        strict=False,
    )
    primary_bound = False
    for component in components:
        if not isinstance(component, Mapping) or set(component) != set(
            _SUPPORTED_DEPENDENCY_RECEIPT_RULE["component_fields"]
        ):
            raise InitError("provider dependency component shape is invalid")
        component_id = component["component_id"]
        kind = component["component_kind"]
        if (
            not isinstance(component_id, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", component_id)
            or component_id in seen
        ):
            raise InitError("provider dependency component identity is duplicate")
        seen.add(component_id)
        component_kinds[component_id] = str(kind)
        if (
            kind
            not in {
                "provider-file",
                "provider-tree",
                "python-distribution",
                "native-runtime",
            }
            or not isinstance(component["source"], str)
            or not component["source"]
            or not isinstance(component["version"], str)
            or not component["version"]
            or not isinstance(component["digest"], str)
            or re.fullmatch(r"[0-9a-f]{64}", component["digest"]) is None
            or not isinstance(component["size_bytes"], int)
            or isinstance(component["size_bytes"], bool)
            or component["size_bytes"] < 0
        ):
            raise InitError(f"provider dependency component is invalid: {component_id}")
        source = _init_identity_path(
            str(component["source"]),
            project_root,
            strict=False,
        )
        if (
            kind == "provider-file"
            and component_id == primary_id
            and source == primary_source
            and component["digest"] == binding["identity"]["digest"]
        ):
            primary_bound = True
    if not primary_bound:
        raise InitError("provider dependency receipt does not bind the invoked provider")
    required_kinds = {primary_id: "provider-file"}
    if invocation_kind == "python-module":
        required_kinds["interpreter"] = "provider-file"
    if capability_id == "shape-validation":
        required_kinds["jsonschema"] = "python-distribution"
    if capability_id == "query-projection":
        required_kinds["sqlite"] = "native-runtime"
    if capability_id == "filesystem-inventory":
        required_kinds["git-provider-tree"] = "provider-tree"
    if capability_id == "shape-validation" and "jsonschema" not in seen:
        raise InitError("shape-validation dependency receipt lacks jsonschema")
    if capability_id == "query-projection" and "sqlite" not in seen:
        raise InitError("query-projection dependency receipt lacks sqlite")
    if capability_id == "filesystem-inventory" and "git-provider-tree" not in seen:
        raise InitError("Git dependency receipt lacks its configured provider tree")
    if binding["invocation"]["kind"] in {"python-runtime", "python-module"} and (
        "interpreter" not in seen
    ):
        raise InitError("Python provider dependency receipt lacks its interpreter")
    if any(component_kinds.get(name) != kind for name, kind in required_kinds.items()):
        raise InitError("provider dependency receipt has an invalid required component")
    identity = {key: deepcopy(receipt[key]) for key in receipt if key != "aggregate_digest"}
    if receipt["aggregate_digest"] != digest_value(identity):
        raise InitError("provider dependency receipt aggregate digest mismatch")
    return components


def verify_provider_dependency_receipt(
    binding: Mapping[str, Any], project_root: Path
) -> None:
    components = _validate_provider_dependency_receipt_shape(binding, project_root)
    primary_source = _init_identity_path(str(binding["identity"]["source"]), project_root)
    for component in components:
        component_id = component["component_id"]
        kind = component["component_kind"]
        source = _init_identity_path(str(component["source"]), project_root)
        if kind in {"provider-file", "native-runtime"}:
            actual_digest = digest_file(source)
            actual_size = source.stat(follow_symlinks=False).st_size
        elif kind == "python-distribution" and component_id == "jsonschema":
            observed = _jsonschema_receipt()
            if resolve_identity_path(str(observed["source"]), strict=True) != source:
                raise InitError("jsonschema dependency source changed")
            actual_digest = str(observed["digest"])
            actual_size = int(observed["size_bytes"])
        elif kind in {"provider-tree", "python-distribution"}:
            if kind == "provider-tree":
                _reject_product_provider_tree_overlap(source, project_root)
            actual_digest, actual_size = _provider_tree_digest(source)
        else:
            raise InitError(f"provider dependency kind is unsupported: {kind}")
        if actual_digest != component["digest"] or actual_size != component["size_bytes"]:
            raise InitError(f"provider dependency component drift: {component_id}")
    if digest_file(primary_source) != binding["identity"]["digest"]:
        raise InitError(f"provider digest mismatch: {binding['provider_id']}")


def _copy_provider_receipt(source: Path, destination: Path, expected: str) -> None:
    """Materialize exact provider bytes through the per-user shared store."""

    try:
        source_mode = source.stat(follow_symlinks=False).st_mode
        if stat.S_ISLNK(source_mode) or not stat.S_ISREG(source_mode):
            raise InitError(f"provider source is not a regular file: {source}")
        materialize_from_store(source, destination, expected)
        fsync_directory(destination.parent)
    except InitError:
        raise
    except Exception as exc:
        raise InitError(f"provider receipt cannot be created: {source}: {exc}") from exc


def _materialize_dependency_component(
    receipt_root: Path,
    binding: Mapping[str, Any],
    component: Mapping[str, Any],
    project_root: Path,
) -> None:
    target = _component_receipt_path(receipt_root, binding, component)
    _make_directory(target, parents=True, exist_ok=False)
    source = _init_identity_path(str(component["source"]), project_root)
    kind = component["component_kind"]
    selected: list[tuple[Path, Path, str]] = []
    if kind in {"provider-file", "native-runtime"}:
        relative = Path("payload" + source.suffix.casefold())
        selected.append((source, relative, str(component["digest"])))
    elif kind == "python-distribution" and component["component_id"] == "jsonschema":
        _distribution, _root, files = _jsonschema_files()
        selected.extend(
            (path, relative, digest_file(path)) for relative, path in files
        )
    elif kind in {"provider-tree", "python-distribution"}:
        files, _total = _provider_tree_files(source)
        selected.extend(
            (
                _provider_tree_source_file(source, source / Path(str(item["path"]))),
                Path(str(item["path"])),
                str(item["digest"]),
            )
            for item in files
        )
    else:
        raise InitError(f"provider dependency kind is unsupported: {kind}")
    for source_path, relative, expected in selected:
        destination = target / relative
        _copy_provider_receipt(source_path, destination, expected)
    for directory, _directories, _filenames in os.walk(target, topdown=False):
        fsync_directory(Path(directory))


def materialize_provider_receipts(
    technologies: Mapping[str, Any],
    project_root: Path,
    receipt_root: Path,
) -> None:
    """Copy verified provider payloads once into immutable content-addressed paths."""

    _make_directory(receipt_root, parents=True, exist_ok=False)
    created: dict[Path, str] = {}
    created_components: dict[Path, str] = {}
    for binding in technologies.get("bindings", []):
        if not isinstance(binding, Mapping):
            raise InitError("provider receipt requires canonical technology bindings")
        verify_provider_dependency_receipt(binding, project_root)
        source = _init_identity_path(str(binding["identity"]["source"]), project_root)
        destination = _provider_receipt_path(receipt_root, binding)
        expected = str(binding["identity"]["digest"])
        previous = created.get(destination)
        if previous is not None:
            if previous != expected:
                raise InitError("provider receipt path collision")
        else:
            _copy_provider_receipt(source, destination, expected)
            created[destination] = expected
        for component in binding["dependency_receipt"]["components"]:
            component_path = _component_receipt_path(receipt_root, binding, component)
            component_digest = str(component["digest"])
            previous_component = created_components.get(component_path)
            if previous_component is not None:
                if previous_component != component_digest:
                    raise InitError("provider dependency receipt path collision")
                continue
            _materialize_dependency_component(receipt_root, binding, component, project_root)
            created_components[component_path] = component_digest
    fsync_directory(receipt_root)


def verify_provider_receipt_inventory(
    technologies: Mapping[str, Any], receipt_root: Path, project_root: Path
) -> None:
    try:
        receipt_mode = os.stat(
            filesystem_path(receipt_root), follow_symlinks=False
        ).st_mode
    except OSError as exc:
        raise InitError(f"provider receipt root is unavailable: {exc}") from exc
    if (
        os.path.islink(filesystem_path(receipt_root))
        or bool(
            getattr(os.path, "isjunction", lambda _value: False)(
                filesystem_path(receipt_root)
            )
        )
        or not stat.S_ISDIR(receipt_mode)
    ):
        raise InitError("provider receipt root must be a real directory")

    expected_files: set[str] = set()
    expected_directories: set[str] = set()
    verified_components: dict[Path, tuple[str, int]] = {}
    for binding in technologies.get("bindings", []):
        components = _validate_provider_dependency_receipt_shape(binding, project_root)
        primary = _provider_receipt_path(receipt_root, binding)
        primary = require_regular_file(primary, root=receipt_root)
        if digest_file(primary) != binding["identity"]["digest"]:
            raise InitError(f"provider receipt digest mismatch: {binding['provider_id']}")
        expected_files.add(primary.relative_to(receipt_root).as_posix())
        expected_directories.add(primary.parent.relative_to(receipt_root).as_posix())
        components_root = primary.parent / "components"
        expected_directories.add(components_root.relative_to(receipt_root).as_posix())
        for component in components:
            target = _component_receipt_path(receipt_root, binding, component)
            expected_directories.add(target.relative_to(receipt_root).as_posix())
            kind = component["component_kind"]
            if kind in {"provider-file", "native-runtime"}:
                suffix = Path(str(component["source"])).suffix.casefold()
                materialized = require_regular_file(
                    target / ("payload" + suffix), root=target
                )
                expected_files.add(materialized.relative_to(receipt_root).as_posix())
                actual_digest = digest_file(materialized)
                actual_size = os.stat(
                    filesystem_path(materialized), follow_symlinks=False
                ).st_size
            elif kind in {"provider-tree", "python-distribution"}:
                actual_digest, actual_size = _provider_tree_digest(target)
                for directory, _directories, filenames in os.walk(
                    _native_path(target), topdown=True, followlinks=False
                ):
                    base = resolve_identity_path(directory, strict=True)
                    for filename in filenames:
                        materialized = require_regular_file(
                            base / filename, root=target
                        )
                        expected_files.add(
                            materialized.relative_to(receipt_root).as_posix()
                        )
                        cursor = materialized.parent
                        while cursor != target:
                            expected_directories.add(
                                cursor.relative_to(receipt_root).as_posix()
                            )
                            cursor = cursor.parent
            else:
                raise InitError(f"provider dependency kind is unsupported: {kind}")
            observed = (actual_digest, actual_size)
            previous = verified_components.get(target)
            if previous is not None and previous != observed:
                raise InitError("provider dependency receipt path collision")
            verified_components[target] = observed
            if (
                actual_digest != component["digest"]
                or actual_size != component["size_bytes"]
            ):
                raise InitError(
                    f"materialized provider dependency receipt drift: {component['component_id']}"
                )
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for directory, directories, filenames in os.walk(
        _native_path(receipt_root), topdown=True, followlinks=False
    ):
        base = resolve_identity_path(directory, strict=True)
        for name in tuple(directories):
            path = base / name
            is_junction = bool(
                getattr(os.path, "isjunction", lambda _value: False)(
                    filesystem_path(path)
                )
            )
            if os.path.islink(filesystem_path(path)) or is_junction:
                raise InitError(f"provider receipt directory is a link: {path}")
            actual_directories.add(path.relative_to(receipt_root).as_posix())
        for name in filenames:
            path = require_regular_file(base / name, root=receipt_root)
            actual_files.add(path.relative_to(receipt_root).as_posix())
    if actual_files != expected_files or actual_directories != expected_directories:
        raise InitError(
            "provider receipt inventory is not exact: "
            f"missing_files={sorted(expected_files - actual_files)[:3]} "
            f"unexpected_files={sorted(actual_files - expected_files)[:3]} "
            f"missing_directories={sorted(expected_directories - actual_directories)[:3]} "
            f"unexpected_directories={sorted(actual_directories - expected_directories)[:3]}"
        )


def _runtime_provider_binding(
    binding: Mapping[str, Any], project_root: Path, receipt_root: Path | None
) -> dict[str, Any]:
    runtime = deepcopy(dict(binding))
    if receipt_root is None:
        return runtime
    receipt = require_regular_file(
        _provider_receipt_path(receipt_root, binding), root=receipt_root
    )
    if digest_file(receipt) != binding["identity"]["digest"]:
        raise InitError(f"provider receipt digest mismatch: {binding['provider_id']}")
    invocation = runtime["invocation"]
    healthcheck = runtime["healthcheck"]
    original_source = _init_identity_path(
        str(binding["identity"]["source"]),
        project_root,
        strict=False,
    )
    # Windows Git is an installation, not a relocatable executable: receipts
    # remain inventory-verified evidence, while operations use the bound host
    # installation so its loader and exec-path dependencies remain available.
    for component in binding["dependency_receipt"]["components"]:
        if component["component_kind"] != "provider-tree":
            continue
        component_source = _init_identity_path(
            str(component["source"]),
            project_root,
            strict=False,
        )
        try:
            relative_source = original_source.relative_to(component_source)
        except ValueError:
            continue
        tree_receipt = _component_receipt_path(receipt_root, binding, component)
        candidate = require_regular_file(
            tree_receipt / relative_source, root=tree_receipt
        )
        if digest_file(candidate) != binding["identity"]["digest"]:
            raise InitError(f"provider tree executable drift: {binding['provider_id']}")
        receipt = candidate
        break
    kind = invocation["kind"]
    if kind == "python-module":
        module_value, separator, callable_name = str(invocation["value"]).rpartition("#")
        if not separator or not callable_name:
            raise InitError(f"provider module invocation is not explicit: {binding['provider_id']}")
        if _init_identity_path(
            module_value, project_root, strict=False
        ) != original_source:
            raise InitError(f"provider invocation does not match its identity: {binding['provider_id']}")
        invocation["value"] = f"{receipt}#{callable_name}"
        argv = list(healthcheck["argv"])
        interpreter_component = next(
            (
                component
                for component in binding["dependency_receipt"]["components"]
                if component["component_id"] == "interpreter"
            ),
            None,
        )
        if interpreter_component is None:
            raise InitError("Python provider dependency receipt lacks its interpreter")
        interpreter_source = _init_identity_path(
            str(interpreter_component["source"]),
            project_root,
            strict=False,
        )
        if (
            len(argv) < 2
            or _init_identity_path(
                str(argv[0]), project_root, strict=False
            ) != interpreter_source
            or _init_identity_path(
                str(argv[1]), project_root, strict=False
            ) != original_source
        ):
            raise InitError(
                f"provider healthcheck does not execute its bound interpreter and module: {binding['provider_id']}"
            )
        interpreter_receipt_root = _component_receipt_path(
            receipt_root, binding, interpreter_component
        )
        interpreter_receipt = require_regular_file(
            interpreter_receipt_root
            / ("payload" + Path(str(interpreter_component["source"])).suffix.casefold()),
            root=interpreter_receipt_root,
        )
        if digest_file(interpreter_receipt) != interpreter_component["digest"]:
            raise InitError(f"provider interpreter receipt drift: {binding['provider_id']}")
        argv[0] = str(interpreter_receipt)
        argv[1] = str(receipt)
        healthcheck["argv"] = argv
    else:
        if (
            _init_identity_path(
                str(invocation["value"]), project_root, strict=False
            ) != original_source
        ):
            raise InitError(f"provider invocation does not match its identity: {binding['provider_id']}")
        invocation["value"] = str(receipt)
        argv = list(healthcheck["argv"])
        if not argv:
            raise InitError(
                f"provider healthcheck does not execute its bound identity: {binding['provider_id']}"
            )
        if _init_identity_path(
            str(argv[0]), project_root, strict=False
        ) != original_source:
            raise InitError(
                f"provider healthcheck does not execute its bound identity: {binding['provider_id']}"
            )
        argv[0] = str(receipt)
        healthcheck["argv"] = argv
    runtime["identity"]["source"] = str(receipt)
    if (
        os.name == "nt"
        and binding.get("capability_id") == "filesystem-inventory"
        and original_source.name.casefold() == "git.exe"
    ):
        runtime["invocation"]["value"] = str(original_source)
        runtime["healthcheck"]["argv"][0] = str(original_source)
    return runtime


def _git_receipt_environment(binding: Mapping[str, Any]) -> Mapping[str, str]:
    executable = Path(str(binding["identity"]["source"]))
    if os.name == "nt" and str(binding["invocation"]["value"]) != str(executable):
        return dict(os.environ)
    digest = str(binding["identity"]["digest"])
    digest_root = next((parent for parent in executable.parents if parent.name == digest[:24]), None)
    if digest_root is None:
        raise InitError("Git provider is not running from a content-addressed receipt")
    provider_tree = digest_root / "components" / "git-provider-tree"
    if not provider_tree.is_dir() or provider_tree.is_symlink():
        raise InitError("Git provider dependency tree receipt is unavailable")
    candidates = [provider_tree] if provider_tree.name == "git-core" else []
    candidates.extend(
        path
        for path in provider_tree.rglob("git-core")
        if path.is_dir() and not path.is_symlink()
    )
    if len(candidates) > 32:
        raise InitError("Git provider tree has an ambiguous exec-path")
    exec_path = next(
        (
            candidate
            for candidate in candidates
            if any(
                (candidate / filename).is_file()
                for filename in ("git-receive-pack", "git-receive-pack.exe")
            )
        ),
        provider_tree,
    )
    environment = dict(os.environ)
    environment["GIT_EXEC_PATH"] = str(exec_path)
    return environment


def _verified_tree_file(
    root: Path,
    relative: Path,
    verified_directories: set[Path],
) -> Path:
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise InitError(f"implementation path escapes its component root: {relative}")
    cursor = root
    for part in relative.parts[:-1]:
        cursor = cursor / part
        if cursor in verified_directories:
            continue
        try:
            mode = cursor.stat(follow_symlinks=False).st_mode
        except OSError as exc:
            raise InitError(f"implementation directory is unavailable: {cursor}: {exc}") from exc
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise InitError(f"implementation directory is not a real directory: {cursor}")
        verified_directories.add(cursor)
    path = root / relative
    try:
        mode = path.stat(follow_symlinks=False).st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise InitError(f"implementation file is not a regular file: {path}")
    except InitError:
        raise
    except OSError as exc:
        raise InitError(f"implementation file is unavailable: {path}: {exc}") from exc
    return path


def _digest_verified_file(path: Path) -> str:
    try:
        result = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                result.update(chunk)
    except OSError as exc:
        raise InitError(f"implementation file is unavailable: {path}: {exc}") from exc
    return result.hexdigest()


def _promin_runtime_version(runtime_root: Path) -> str:
    version_path = runtime_root.parent / "VERSION.json"
    if version_path.is_file() and not version_path.is_symlink():
        value = load_json_strict(version_path, root=runtime_root.parent)
        version = value.get("version") if isinstance(value, Mapping) else None
        if isinstance(version, str) and version:
            return version
    try:
        distribution = importlib_metadata.distribution("promin")
        installed_package = resolve_identity_path(distribution.locate_file("promin"), strict=True)
        if installed_package == resolve_identity_path(runtime_root, strict=True):
            return distribution.version
    except (importlib_metadata.PackageNotFoundError, OSError):
        pass
    raise InitError("Promin runtime version is unavailable")


def _promin_runtime_files(runtime_root: Path) -> tuple[tuple[Path, Path], ...]:
    verified_directories = {runtime_root}
    files = tuple(
        (
            path.relative_to(runtime_root),
            _verified_tree_file(
                runtime_root,
                path.relative_to(runtime_root),
                verified_directories,
            ),
        )
        for path in sorted(
            runtime_root.rglob("*.py"),
            key=lambda item: item.relative_to(runtime_root).as_posix(),
        )
    )
    if not files:
        raise InitError("Promin runtime implementation has no bindable modules")
    return files


def _promin_runtime_receipt() -> dict[str, str]:
    runtime_root = resolve_identity_path(__file__, strict=True).parent
    files = [
        {"path": relative.as_posix(), "digest": _digest_verified_file(path)}
        for relative, path in _promin_runtime_files(runtime_root)
    ]
    version = _promin_runtime_version(runtime_root)
    return {
        "name": "promin",
        "version": version,
        "digest": digest_value(
            {
                "name": "promin",
                "version": version,
                "files": files,
            }
        ),
    }


def _interpreter_receipt() -> dict[str, str]:
    executable_path = resolve_identity_path(sys.executable, strict=True)
    executable = require_regular_file(executable_path, root=executable_path.parent)
    return {
        "name": sys.implementation.name,
        "version": platform.python_version(),
        "executable_digest": digest_file(executable),
    }


def _jsonschema_files() -> tuple[Any, Path, tuple[tuple[Path, Path], ...]]:
    try:
        distribution = importlib_metadata.distribution("jsonschema")
    except importlib_metadata.PackageNotFoundError as exc:
        raise InitError("jsonschema distribution is unavailable") from exc
    distribution_base = Path(distribution.locate_file(".")).absolute()
    distribution_root = resolve_identity_path(distribution_base, strict=True)
    selected_files: list[tuple[Path, Path]] = []
    verified_directories = {distribution_root}
    for item in distribution.files or ():
        relative = Path(str(item).replace("\\", "/"))
        parts = relative.parts
        if not parts or "__pycache__" in parts or relative.suffix in {".pyc", ".pyo"}:
            continue
        package_file = parts[0] == "jsonschema"
        metadata_file = (
            parts[0].casefold().startswith("jsonschema-")
            and parts[0].casefold().endswith(".dist-info")
            and len(parts) == 2
            and parts[1] in {"METADATA", "RECORD", "entry_points.txt", "top_level.txt"}
        )
        if not package_file and not metadata_file:
            continue
        selected_files.append(
            (
                relative,
                _verified_tree_file(
                    distribution_root, relative, verified_directories
                ),
            )
        )
    selected_files.sort(key=lambda value: value[0].as_posix())
    if not selected_files:
        raise InitError("jsonschema distribution has no bindable implementation files")
    return distribution, distribution_root, tuple(selected_files)


def _jsonschema_receipt() -> dict[str, Any]:
    distribution, _distribution_root, selected_files = _jsonschema_files()
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(selected_files)))) as pool:
        digests = tuple(pool.map(_digest_verified_file, (item[1] for item in selected_files)))
    files = [
        {
            "path": item[0].as_posix(),
            "digest": digest,
            "size_bytes": item[1].stat(follow_symlinks=False).st_size,
        }
        for item, digest in zip(selected_files, digests, strict=True)
    ]
    return {
        "component_id": "jsonschema",
        "component_kind": "python-distribution",
        "source": str(_distribution_root),
        "version": distribution.version,
        "digest": digest_value(
            {"record_type": "ProviderTreeReceipt", "files": files}
        ),
        "size_bytes": sum(int(item["size_bytes"]) for item in files),
    }


def _sqlite_receipt() -> dict[str, Any]:
    module_source = resolve_identity_path(_sqlite3.__file__, strict=True)
    module_path = require_regular_file(module_source, root=module_source.parent)
    return {
        "component_id": "sqlite",
        "component_kind": "native-runtime",
        "source": str(module_path),
        "version": sqlite3.sqlite_version,
        "digest": digest_file(module_path),
        "size_bytes": module_path.stat(follow_symlinks=False).st_size,
    }


def _implementation_environment() -> tuple[dict[str, str], dict[str, str]]:
    return _promin_runtime_receipt(), _interpreter_receipt()


def _implementation_closure(
    binding: Mapping[str, Any],
    adapter: ProviderAdapter,
    environment: tuple[dict[str, str], dict[str, str]],
) -> dict[str, Any]:
    runtime, interpreter = environment
    components = deepcopy(binding["dependency_receipt"]["components"])
    adapter_identity = {
        "adapter_id": adapter.adapter_id,
        "capability_id": adapter.capability_id,
        "version": runtime["version"],
        "provider_id": adapter.provider_id,
        "provider_version": binding["version"],
        "invocation_kind": adapter.invocation_kind,
        "identity_kind": adapter.identity_kind,
        "identity_digest": adapter.identity_digest,
        "protocol_id": adapter.protocol_id,
        "operation_contract_digest": adapter.operation_contract_digest,
        "dependency_receipt_digest": adapter.dependency_receipt_digest,
        "runtime_digest": runtime["digest"],
    }
    adapter_receipt = {
        "adapter_id": adapter.adapter_id,
        "capability_id": adapter.capability_id,
        "version": runtime["version"],
        "digest": digest_value(adapter_identity),
        "protocol_id": adapter.protocol_id,
        "operation_contract_digest": adapter.operation_contract_digest,
        "dependency_receipt_digest": adapter.dependency_receipt_digest,
    }
    identity: dict[str, Any] = {
        "runtime": dict(runtime),
        "interpreter": dict(interpreter),
        "components": components,
        "adapters": [adapter_receipt],
    }
    return {**identity, "closure_digest": digest_value(identity)}


def implementation_closure_digest(technologies: Mapping[str, Any]) -> str:
    receipts = sorted(
        (
            {
                "capability_id": binding["capability_id"],
                "provider_id": binding["provider_id"],
                "closure_digest": binding["implementation_closure"]["closure_digest"],
            }
            for binding in technologies["bindings"]
        ),
        key=lambda item: (str(item["capability_id"]), str(item["provider_id"])),
    )
    return digest_value({"record_type": "ImplementationClosureSet", "bindings": receipts})


def verify_implementation_closures(
    technologies: Mapping[str, Any], provider_dispatch: ProviderDispatch
) -> None:
    environment = _implementation_environment()
    for binding in technologies["bindings"]:
        capability_id = str(binding["capability_id"])
        expected = _implementation_closure(
            binding,
            provider_dispatch.adapter(capability_id),
            environment,
        )
        if binding.get("implementation_closure") != expected:
            raise InitError(f"implementation closure drift: {capability_id}")


def bind_implementation_closures(
    technologies: Mapping[str, Any],
    project_root: str | Path,
    provider_verifiers: Mapping[str, ProviderVerifier] | None = None,
    *,
    contract_bundle: ContractBundle | None = None,
    signature_verifier: SignatureVerifier | None = None,
) -> dict[str, Any]:
    """Return a TechnologiesInit value bound to implementations running now."""

    bound = deepcopy(dict(technologies))
    for binding in bound.get("bindings", []):
        if isinstance(binding, dict):
            binding.pop("implementation_closure", None)
    dispatch = resolve_provider_dispatch(
        bound,
        resolve_identity_path(project_root, strict=True),
        provider_verifiers,
        contract_bundle=contract_bundle,
        signature_verifier=signature_verifier,
        verify_implementation=False,
    )
    environment = _implementation_environment()
    for binding in bound["bindings"]:
        capability_id = str(binding["capability_id"])
        binding["implementation_closure"] = _implementation_closure(
            binding,
            dispatch.adapter(capability_id),
            environment,
        )
    return bound


def _verify_file_provider(identity: Mapping[str, Any], project_root: Path) -> str:
    source = Path(identity["source"])
    if not source.is_absolute():
        source = project_root / source
    return digest_file(source)


DEFAULT_PROVIDER_VERIFIERS: Mapping[str, ProviderVerifier] = {
    "file-digest": _verify_file_provider,
    "module-file-digest": _verify_file_provider,
}


def _native_path(path: Path) -> str:
    absolute = str(path.absolute())
    if os.name != "nt" or absolute.startswith("\\\\?\\"):
        return absolute
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute[2:]
    return "\\\\?\\" + absolute


def _extended_path(path: Path) -> Path:
    return Path(_native_path(path))


def _make_directory(
    path: Path,
    *,
    mode: int = 0o777,
    parents: bool = False,
    exist_ok: bool = False,
) -> None:
    """Create an owner-managed directory at the final filesystem boundary.

    Init records retain ordinary canonical paths.  Windows extended-length
    spelling is used only for the OS call because a project root can validly
    place its private staging tree beyond the historical Win32 path limit.
    """

    native = _native_path(path)
    if parents:
        os.makedirs(native, mode=mode, exist_ok=exist_ok)
        return
    try:
        os.mkdir(native, mode=mode)
    except FileExistsError:
        if not exist_ok:
            raise


@dataclass(frozen=True)
class InitRequest:
    project_root: Path
    standard_bundle: Path
    preset_path: Path
    project_plan: Path
    standards_plan: Path
    technologies_plan: Path
    licenses_plan: Path
    authority_plan: Path
    activation_proofs: Sequence[Mapping[str, Any]] | None = None
    provider_verifiers: Mapping[str, ProviderVerifier] = field(default_factory=dict)
    signature_verifier: SignatureVerifier | None = None


@dataclass(frozen=True)
class ActivationContext:
    project_root: Path
    control_root: Path
    installed_standard: Path
    bundle: ContractBundle
    plans: Mapping[str, Any]
    activation: Mapping[str, Any]
    provider_dispatch: ProviderDispatch
    authoritative_byte_digest: str | None = None

    @property
    def activation_digest(self) -> str:
        return str(self.activation["activation_digest"])

    @property
    def operating_profile(self) -> str:
        return str(self.activation["operating_profile"])

    @property
    def implementation_closure_digest(self) -> str:
        return str(self.activation["implementation_closure_digest"])

    @property
    def implementation_closure(self) -> Mapping[str, Mapping[str, Any]]:
        return {
            str(binding["capability_id"]): deepcopy(binding["implementation_closure"])
            for binding in self.plans["technologies.json"]["bindings"]
        }

    @property
    def continuation_secret(self) -> bytes:
        return _load_continuation_secret(self.control_root, self.activation_digest)

    @property
    def signature_verifier(self) -> SignatureVerifier | None:
        if self.activation["trust_mode"] != "team-signed":
            return None
        return self.provider_dispatch.signature_verifier()


def _read_path_state(label: str, path: Path, kind: str) -> dict[str, Any]:
    try:
        value = os.stat(filesystem_path(path), follow_symlinks=False)
    except OSError as exc:
        raise InitError(f"Activation-bound path is unavailable: {path}: {exc}") from exc
    valid_kind = (
        kind == "file" and stat.S_ISREG(value.st_mode)
    ) or (
        kind == "directory" and stat.S_ISDIR(value.st_mode)
    )
    # ``stat(..., follow_symlinks=False)`` already carries the symbolic-link
    # bit, so a second ``os.path.islink`` would repeat the same I/O for every
    # Activation-bound path on every cache guard.
    if stat.S_ISLNK(value.st_mode) or not valid_kind:
        raise InitError(f"Activation-bound path is not a real {kind}: {path}")
    return {
        "label": label,
        "path": str(path.absolute()),
        "kind": kind,
        "mode": int(value.st_mode),
        "device": int(value.st_dev),
        "inode": int(value.st_ino),
        "size": int(value.st_size),
        "modified_ns": int(value.st_mtime_ns),
        "changed_ns": int(value.st_ctime_ns),
    }


def activation_read_bindings(
    context: ActivationContext,
) -> tuple[tuple[str, Path, str], ...]:
    """Compile exact Activation-bound paths for byte verification and read caching."""

    control = context.control_root
    activation_digest = context.activation_digest
    core_dir = _extended_path(context.bundle.core_dir)
    preset_path = _extended_path(context.bundle.preset_path)
    secret_dir = control / "state" / "secrets"
    secret_name = f"{activation_digest}.continuation.key"

    selected: list[tuple[str, Path, str]] = [
        ("directory/init", control / "init", "directory"),
        ("directory/core", core_dir, "directory"),
        ("directory/continuation-secret", secret_dir, "directory"),
        ("directory/preset", preset_path.parent, "directory"),
    ]
    selected.extend(
        (f"init/{filename}", path, "file")
        for filename, path in zip(
            INIT_FILES,
            ensure_exact_regular_files(control / "init", INIT_FILES),
            strict=True,
        )
    )
    selected.extend(
        (f"core/{filename}", path, "file")
        for filename, path in zip(
            CORE_FILES,
            ensure_exact_regular_files(core_dir, CORE_FILES),
            strict=True,
        )
    )
    selected.append(
        (
            "preset/selected",
            require_regular_file(preset_path, root=preset_path.parent),
            "file",
        )
    )
    (secret_path,) = ensure_exact_regular_files(secret_dir, (secret_name,))
    selected.append(("continuation-secret", secret_path, "file"))

    runtime_root = resolve_identity_path(__file__, strict=True).parent
    runtime_files = _promin_runtime_files(runtime_root)
    selected.extend(
        (f"runtime/{relative.as_posix()}", path, "file")
        for relative, path in runtime_files
    )
    selected.extend(
        (
            f"directory/runtime/{path.relative_to(runtime_root).as_posix() or '.'}",
            path,
            "directory",
        )
        for path in sorted(
            {runtime_root, *(item[1].parent for item in runtime_files)},
            key=lambda item: str(item),
        )
    )
    version_path = runtime_root.parent / "VERSION.json"
    if version_path.exists():
        selected.append(
            (
                "runtime/VERSION.json",
                require_regular_file(version_path, root=runtime_root.parent),
                "file",
            )
        )

    interpreter = resolve_identity_path(sys.executable, strict=True)
    selected.append(
        (
            "runtime/python",
            require_regular_file(interpreter, root=interpreter.parent),
            "file",
        )
    )
    _jsonschema_distribution, _jsonschema_root, jsonschema_files = _jsonschema_files()
    selected.extend(
        (f"runtime/jsonschema/{relative.as_posix()}", path, "file")
        for relative, path in jsonschema_files
    )
    sqlite_source = resolve_identity_path(_sqlite3.__file__, strict=True)
    selected.append(
        (
            "runtime/sqlite",
            require_regular_file(sqlite_source, root=sqlite_source.parent),
            "file",
        )
    )
    for binding in sorted(
        context.plans["technologies.json"]["bindings"],
        key=lambda item: (str(item["capability_id"]), str(item["provider_id"])),
    ):
        runtime_binding = context.provider_dispatch.binding(str(binding["capability_id"]))
        receipt = _init_identity_path(
            str(runtime_binding["identity"]["source"]), context.project_root
        )
        selected.append(
            (
                f"provider-receipt/{binding['capability_id']}/{binding['provider_id']}",
                require_regular_file(receipt, root=context.control_root / "providers"),
                "file",
            )
        )
        digest_root = _provider_receipt_path(
            context.control_root / "providers", binding
        ).parent
        for directory, _directories, filenames in os.walk(
            digest_root / "components", topdown=True, followlinks=False
        ):
            base = Path(directory)
            selected.extend(
                (
                    f"provider-dependency-receipt/{binding['provider_id']}/"
                    f"{(base / filename).relative_to(digest_root / 'components').as_posix()}",
                    require_regular_file(base / filename, root=digest_root / "components"),
                    "file",
                )
                for filename in filenames
            )

    bindings: list[tuple[str, Path, str]] = []
    seen: set[tuple[str, str]] = set()
    for label, path, kind in sorted(
        selected,
        key=lambda value: (value[2], os.path.normcase(str(value[1].absolute())), value[0]),
    ):
        key = (kind, os.path.normcase(str(path.absolute())))
        if key in seen:
            continue
        seen.add(key)
        bindings.append((label, path, kind))
    return tuple(bindings)


def activation_read_fingerprint(
    context: ActivationContext,
    bindings: Sequence[tuple[str, Path, str]] | None = None,
) -> str:
    """Return metadata for non-authoritative read-cache reuse only.

    This value MUST NOT skip ActivationGuard.verify_authoritative_mutation() or
    authorize a command, mutation, replay, rebuild, import, or export.
    """

    selected = activation_read_bindings(context) if bindings is None else tuple(bindings)
    states = [
        _read_path_state(label, path, kind)
        for label, path, kind in selected
    ]
    return digest_value({"paths": states})


def activation_byte_digest(
    context: ActivationContext,
    bindings: Sequence[tuple[str, Path, str]] | None = None,
) -> str:
    """Digest the exact bytes used by a verified Activation context."""

    selected = activation_read_bindings(context) if bindings is None else tuple(bindings)
    files: list[dict[str, Any]] = []
    directories: list[dict[str, Any]] = []
    for label, path, kind in selected:
        if kind == "file":
            regular = require_regular_file(path, root=path.parent)
            files.append(
                {
                    "label": label,
                    "path": str(path.absolute()),
                    "sha256": digest_file(regular),
                    "bytes": os.stat(filesystem_path(regular), follow_symlinks=False).st_size,
                }
            )
        else:
            state = _read_path_state(label, path, kind)
            directories.append(
                {
                    "label": label,
                    "path": state["path"],
                    "kind": state["kind"],
                }
            )
    return digest_value({"files": files, "directories": directories})


@dataclass(frozen=True)
class InitPreflightReceipt:
    """Transient proof that every configured provider preflight completed."""

    provider_count: int
    observation_digests: tuple[str, ...]
    receipt_digest: str


def _init_preflight_receipt(
    observations: Sequence[Mapping[str, Any]],
) -> InitPreflightReceipt:
    observation_digests = tuple(digest_value(observation) for observation in observations)
    return InitPreflightReceipt(
        provider_count=len(observation_digests),
        observation_digests=observation_digests,
        receipt_digest=digest_value(
            {"observation_digests": list(observation_digests)}
        ),
    )


@dataclass(frozen=True)
class InitResult:
    context: ActivationContext
    created: bool
    preflight_receipt: InitPreflightReceipt

    @property
    def idempotent(self) -> bool:
        return not self.created


def _provider_input_identities(
    technologies: Mapping[str, Any],
    project_root: Path,
    *,
    receipt_root: Path | None,
) -> list[dict[str, Any]]:
    """Return path-free provider identities after verifying their actual bytes."""

    bindings = technologies.get("bindings")
    if not isinstance(bindings, list):
        raise InitError("TechnologiesInit provider bindings are unavailable")
    if receipt_root is None:
        for binding in bindings:
            verify_provider_dependency_receipt(binding, project_root)
    else:
        verify_provider_receipt_inventory(technologies, receipt_root, project_root)
    identities: list[dict[str, Any]] = []
    for binding in sorted(
        bindings,
        key=lambda item: (str(item["capability_id"]), str(item["provider_id"])),
    ):
        dependency = binding.get("dependency_receipt")
        closure = binding.get("implementation_closure")
        if not isinstance(dependency, Mapping) or not isinstance(closure, Mapping):
            raise InitError("provider identity lacks its dependency or implementation receipt")
        identities.append(
            {
                "capability_id": binding["capability_id"],
                "provider_id": binding["provider_id"],
                "identity_digest": binding["identity"]["digest"],
                "dependency_receipt_digest": dependency["aggregate_digest"],
                "implementation_closure_digest": closure["closure_digest"],
                "components": [
                    {
                        "component_id": component["component_id"],
                        "component_kind": component["component_kind"],
                        "digest": component["digest"],
                        "size_bytes": component["size_bytes"],
                    }
                    for component in dependency["components"]
                ],
            }
        )
    return identities


def _init_input_identity(
    bundle: ContractBundle,
    plans: Mapping[str, Any],
    licenses: Mapping[str, Any],
    activation: Mapping[str, Any],
    project_root: Path,
    *,
    provider_receipt_root: Path | None,
) -> dict[str, Any]:
    """Recompute the complete transient identity needed to publish initialization."""

    plan_inputs = {**plans, "licenses.json": licenses}
    init_records = {**plans, "activation.json": activation}
    if set(plan_inputs) != {*PLAN_FILES, "licenses.json"}:
        raise InitError("init input identity requires exactly five explicit plans")
    if set(init_records) != set(INIT_FILES):
        raise InitError("init input identity requires exactly five init records")
    core_files = {
        filename: {
            "digest": digest_file(bundle.core_dir / filename, root=bundle.core_dir),
            "size_bytes": os.stat(
                filesystem_path(bundle.core_dir / filename), follow_symlinks=False
            ).st_size,
        }
        for filename in CORE_FILES
    }
    identity = {
        "core_bundle_digest": bundle.bundle_digest,
        "core_file_identities": core_files,
        "preset_digest": digest_file(
            bundle.preset_path, root=bundle.preset_path.parent
        ),
        "provider_identities": _provider_input_identities(
            plans["technologies.json"],
            project_root,
            receipt_root=provider_receipt_root,
        ),
        "implementation_closure_digest": implementation_closure_digest(
            plans["technologies.json"]
        ),
        "init_plan_digests": {
            filename: digest_value(plan_inputs[filename])
            for filename in (*PLAN_FILES, "licenses.json")
        },
        "init_record_digests": {
            filename: digest_value(init_records[filename]) for filename in INIT_FILES
        },
        "activation_digest": activation["activation_digest"],
        "product_tree_scans": 0,
    }
    return {**identity, "identity_digest": digest_value(identity)}


def _require_same_init_input_identity(
    expected: Mapping[str, Any],
    actual: Mapping[str, Any],
    *,
    boundary: str,
) -> None:
    if dict(actual) != dict(expected):
        raise InitError(f"init input identity changed before {boundary}")


def _preflight_init_inputs(
    request: InitRequest,
    project_root: Path,
    bundle: ContractBundle,
    plans: Mapping[str, Any],
    licenses: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], InitPreflightReceipt]:
    """Verify all input bytes and provider execution outside the product project."""

    with resolved_temporary_directory(prefix="promin-v1-init-preflight-") as temporary:
        receipt_root = temporary / "providers"
        materialize_provider_receipts(
            plans["technologies.json"], project_root, receipt_root
        )
        verify_provider_receipt_inventory(
            plans["technologies.json"], receipt_root, project_root
        )
        dispatch = resolve_provider_dispatch(
            plans["technologies.json"],
            project_root,
            request.provider_verifiers,
            contract_bundle=bundle,
            receipt_root=receipt_root,
            signature_verifier=request.signature_verifier,
            require_configured_healthcheck_paths=True,
        )
        observations = verify_provider_preflight(
            plans["technologies.json"],
            project_root,
            contract_bundle=bundle,
            provider_dispatch=dispatch,
            receipt_root=receipt_root,
        )
        selected_verifier = (
            dispatch.signature_verifier()
            if plans["authority.json"]["trust_mode"] == "team-signed"
            else None
        )
        activation = _make_activation(
            bundle,
            plans,
            request.activation_proofs,
            selected_verifier,
        )
        identity = _init_input_identity(
            bundle,
            plans,
            licenses,
            activation,
            project_root,
            provider_receipt_root=receipt_root,
        )
    return activation, identity, _init_preflight_receipt(observations)


def _staged_init_input_identity(
    staging_control: Path,
    expected: Mapping[str, Any],
    licenses: Mapping[str, Any],
    project_root: Path,
) -> dict[str, Any]:
    """Re-read staged authority and reproduce its transient preflight identity."""

    bundle_digest = str(expected["core_bundle_digest"])
    preset_digest = str(expected["preset_digest"])
    installed = staging_control / "standard" / bundle_digest
    preset_path = installed / "presets" / f"{preset_digest}.json"
    staged_bundle = load_contract_bundle(installed, _extended_path(preset_path))
    init_dir = staging_control / "init"
    ensure_exact_regular_files(init_dir, INIT_FILES)
    records = {
        filename: load_json_strict(init_dir / filename, root=init_dir)
        for filename in INIT_FILES
    }
    staged_plans = {filename: records[filename] for filename in PLAN_FILES}
    activation = records["activation.json"]
    return _init_input_identity(
        staged_bundle,
        staged_plans,
        licenses,
        activation,
        project_root,
        provider_receipt_root=staging_control / "providers",
    )


def _validate_project_bound_authority(plans: Mapping[str, Any]) -> None:
    project = plans.get("project.json")
    authority = plans.get("authority.json")
    project_id = project.get("project_id") if isinstance(project, Mapping) else None
    roots = authority.get("roots") if isinstance(authority, Mapping) else None
    if not isinstance(project_id, str) or not project_id or not isinstance(roots, list):
        raise InitError("init authority cannot be bound to the explicit project")
    for root in roots:
        scopes = root.get("scope") if isinstance(root, Mapping) else None
        if (
            not isinstance(scopes, list)
            or not scopes
            or any(not isinstance(scope, Mapping) for scope in scopes)
            or any(scope.get("kind") == "all" for scope in scopes)
            or any(
                scope.get("kind") == "project" and scope.get("value") != project_id
                for scope in scopes
            )
            or not any(
                scope.get("kind") == "project" and scope.get("value") == project_id
                for scope in scopes
            )
        ):
            raise InitError("every init authority root must be bound to the exact project")


def build_explicit_init_plan(
    *,
    standard_bundle: str | Path,
    preset_path: str | Path,
    project_root: str | Path,
    project_plan: Mapping[str, Any],
    standards_plan: Mapping[str, Any],
    technologies_plan: Mapping[str, Any],
    licenses_plan: Mapping[str, Any],
    authority_plan: Mapping[str, Any],
    activation_proofs: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Validate an entirely explicit init envelope without inventing policy."""

    supplied_target = Path(project_root)
    if supplied_target.is_symlink():
        raise InitError("project root symbolic link rejected")
    target = resolve_identity_path(supplied_target, strict=True)
    if not target.is_dir():
        raise InitError("project root must be a real existing directory")
    package = resolve_identity_path(standard_bundle, strict=True)
    preset = resolve_identity_path(preset_path, strict=True)
    bundle = load_contract_bundle(package, preset)
    explicit_records = {
        "project.json": project_plan,
        "standards.json": standards_plan,
        "technologies.json": technologies_plan,
        "authority.json": authority_plan,
        "licenses.json": licenses_plan,
    }
    if any(not isinstance(value, Mapping) for value in explicit_records.values()):
        raise InitError("every explicit init plan must be a JSON object")
    plans = {
        "project.json": compile_project_init(project_plan, bundle),
        "standards.json": deepcopy(dict(standards_plan)),
        "technologies.json": deepcopy(dict(technologies_plan)),
        "authority.json": deepcopy(dict(authority_plan)),
    }
    licenses = deepcopy(dict(licenses_plan))
    validate_plan_objects(plans, bundle, licenses)
    _validate_project_bound_authority(plans)
    return {
        "record_type": "ExplicitInitPlan",
        "standard_bundle": str(package),
        "preset_path": str(preset),
        "project_root": str(target),
        "plans": plans,
        "licenses": licenses,
        "activation_proofs": deepcopy(list(activation_proofs))
        if activation_proofs is not None
        else None,
        "implementation_closure_digest": implementation_closure_digest(
            plans["technologies.json"]
        ),
        "product_tree_scans": 0,
    }


def initialize_explicit_init_plan(
    plan: Mapping[str, Any],
    *,
    project_root: str | Path | None = None,
) -> InitResult:
    """Apply a validated explicit envelope through the canonical InitRequest path."""

    if (
        set(plan)
        != {
            "record_type",
            "standard_bundle",
            "preset_path",
            "project_root",
            "plans",
            "licenses",
            "activation_proofs",
            "implementation_closure_digest",
            "product_tree_scans",
        }
        or plan.get("record_type") != "ExplicitInitPlan"
        or plan.get("product_tree_scans") != 0
    ):
        raise InitError("only an explicit zero-scan init plan is accepted")
    target = resolve_identity_path(project_root or str(plan.get("project_root", "")), strict=True)
    if target != resolve_identity_path(str(plan.get("project_root", "")), strict=True):
        raise InitError("project root changed after explicit init plan construction")
    plans = plan.get("plans")
    licenses = plan.get("licenses")
    if not isinstance(plans, Mapping) or not isinstance(licenses, Mapping):
        raise InitError("explicit init plan records are unavailable")
    if plan.get("implementation_closure_digest") != implementation_closure_digest(
        plans["technologies.json"]
    ):
        raise InitError("implementation closure changed after plan construction")
    with resolved_temporary_directory(prefix="promin-v1-explicit-init-") as plan_root:
        paths: dict[str, Path] = {}
        for filename in PLAN_FILES:
            path = plan_root / filename
            with path.open("xb") as handle:
                handle.write(canonical_bytes(plans[filename]))
            paths[filename] = path
        licenses_path = plan_root / "licenses.json"
        with licenses_path.open("xb") as handle:
            handle.write(canonical_bytes(licenses))
        request = InitRequest(
            project_root=target,
            standard_bundle=Path(str(plan["standard_bundle"])),
            preset_path=Path(str(plan["preset_path"])),
            project_plan=paths["project.json"],
            standards_plan=paths["standards.json"],
            technologies_plan=paths["technologies.json"],
            licenses_plan=licenses_path,
            authority_plan=paths["authority.json"],
            activation_proofs=plan.get("activation_proofs"),
        )
        return initialize_project(request)


def apply_explicit_init_plan(
    project_root: str | Path, plan: Mapping[str, Any]
) -> dict[str, Any]:
    result = initialize_explicit_init_plan(plan, project_root=project_root)
    return {
        "record_type": "InitResult",
        "status": "created" if result.created else "idempotent",
        "activation_digest": result.context.activation_digest,
        "core_bundle_digest": result.context.activation["core_bundle_digest"],
        "preset_digest": result.context.activation["preset_digest"],
        "implementation_closure_digest": result.context.implementation_closure_digest,
        "product_tree_scans": 0,
    }


def emit_canonical_init_plans(
    output_directory: str | Path,
    *,
    project_root: str | Path,
    standard_bundle: str | Path,
    preset_path: str | Path,
    project_plan: Mapping[str, Any],
    standards_plan: Mapping[str, Any],
    technologies_plan: Mapping[str, Any],
    licenses_plan: Mapping[str, Any],
    authority_plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Atomically emit five explicit validated plans outside project control state."""

    explicit = build_explicit_init_plan(
        standard_bundle=standard_bundle,
        preset_path=preset_path,
        project_root=project_root,
        project_plan=project_plan,
        standards_plan=standards_plan,
        technologies_plan=technologies_plan,
        licenses_plan=licenses_plan,
        authority_plan=authority_plan,
    )
    plans = explicit["plans"]
    licenses = explicit["licenses"]
    bundle = load_contract_bundle(standard_bundle, preset_path)
    target = Path(output_directory).absolute()
    if target.exists() or target.is_symlink():
        raise InitError("init plan output directory already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = target.parent / f".{target.name}.p-{uuid.uuid4().hex[:12]}"
    records = {**plans, "licenses.json": licenses}
    try:
        staging.mkdir()
        for filename, value in records.items():
            with (staging / filename).open("xb") as handle:
                handle.write(canonical_bytes(value))
                handle.flush()
                os.fsync(handle.fileno())
        ensure_exact_regular_files(staging, (*PLAN_FILES, "licenses.json"))
        fsync_directory(staging)
        os.rename(staging, target)
        fsync_directory(target.parent)
    except BaseException:
        if staging.exists():
            _remove_staging(staging)
        if portable_shell_backup is not None and portable_shell_backup.exists():
            try:
                if not control.exists():
                    os.rename(portable_shell_backup, control)
                    fsync_directory(project_root)
                elif control.is_dir() and not control.is_symlink():
                    _merge_portable_control_shell(portable_shell_backup, control)
                    shutil.rmtree(portable_shell_backup)
            except OSError:
                pass
        raise
    return {
        "record_type": "InitPlanEmission",
        "status": "created",
        "canonical_name": "promin",
        "standard_version": bundle.manifest["version"],
        "core_bundle_digest": bundle.bundle_digest,
        "preset_digest": bundle.preset_digest,
        "output_directory": str(target),
        "files": [
            {"path": filename, "digest": digest_value(records[filename])}
            for filename in (*PLAN_FILES, "licenses.json")
        ],
        "product_tree_scans": 0,
        "project_mutations": 0,
        "product_acceptance_pass": False,
        "product_public_approval": "not_approved",
    }


def review_init_request(request: InitRequest, *, run_preflight: bool) -> dict[str, Any]:
    """Validate an init request and explain its bindings without writing project state."""

    supplied_root = Path(request.project_root)
    if supplied_root.is_symlink():
        raise InitError("project root symbolic link rejected")
    project_root = resolve_identity_path(supplied_root, strict=True)
    if not project_root.is_dir():
        raise InitError("project root must be a real existing directory")
    bundle = load_contract_bundle(request.standard_bundle, request.preset_path)
    plans, licenses = _load_plan_files(request, bundle)
    validate_plan_objects(plans, bundle, licenses)
    _validate_project_bound_authority(plans)
    temporary_context = (
        resolved_temporary_directory(prefix="promin-v1-provider-review-")
        if run_preflight
        else nullcontext(None)
    )
    with temporary_context as temporary_root:
        receipt_root = temporary_root / "providers" if temporary_root is not None else None
        if run_preflight:
            materialize_provider_receipts(
                plans["technologies.json"], project_root, receipt_root
            )
            verify_provider_receipt_inventory(
                plans["technologies.json"], receipt_root, project_root
            )
        dispatch = resolve_provider_dispatch(
            plans["technologies.json"],
            project_root,
            request.provider_verifiers,
            contract_bundle=bundle,
            receipt_root=receipt_root,
            signature_verifier=request.signature_verifier,
        )
        if run_preflight:
            verify_provider_preflight(
                plans["technologies.json"],
                project_root,
                contract_bundle=bundle,
                provider_dispatch=dispatch,
                receipt_root=receipt_root,
            )
        selected_verifier = (
            dispatch.signature_verifier()
            if plans["authority.json"]["trust_mode"] == "team-signed"
            else None
        )
        activation = _make_activation(
            bundle,
            plans,
            request.activation_proofs,
            selected_verifier,
        )
    technologies = plans["technologies.json"]
    return {
        "record_type": "InitPlanReview",
        "status": "pass",
        "mode": "dry-run" if run_preflight else "review",
        "canonical_name": "promin",
        "standard_version": bundle.manifest["version"],
        "project_root": str(project_root),
        "core_bundle_digest": bundle.bundle_digest,
        "preset_digest": bundle.preset_digest,
        "plan_digests": {
            filename: digest_value(plans[filename]) for filename in PLAN_FILES
        }
        | {"licenses.json": digest_value(licenses)},
        "provider_bindings": [
            {
                "capability_id": item["capability_id"],
                "provider_id": item["provider_id"],
                "required": item["required"],
                "identity_digest": item["identity"]["digest"],
                "implementation_closure_digest": item["implementation_closure"][
                    "closure_digest"
                ],
                "license_expression": item["license"]["expression"],
            }
            for item in technologies["bindings"]
        ],
        "authority_binding": {
            "trust_mode": plans["authority.json"]["trust_mode"],
            "subjects": [
                item["subject_id"] for item in plans["authority.json"]["subjects"]
            ],
            "roots": [
                {
                    "subject_id": item["subject_id"],
                    "capability_ceiling": list(item["capability_ceiling"]),
                    "scope": deepcopy(item["scope"]),
                }
                for item in plans["authority.json"]["roots"]
            ],
        },
        "activation_digest": activation["activation_digest"],
        "implementation_closure_digest": activation[
            "implementation_closure_digest"
        ],
        "provider_preflight": "pass" if run_preflight else "not_run",
        "would_create_init_records": list(INIT_FILES),
        "would_create_init_record_count": len(INIT_FILES),
        "would_install_standard_at": str(
            project_root / ".promin" / "standard" / bundle.bundle_digest
        ),
        "product_tree_scans": 0,
        "mutations_performed": 0,
        "product_acceptance_pass": False,
        "product_public_approval": "not_approved",
    }


def _load_plan_files(
    request: InitRequest, bundle: ContractBundle
) -> tuple[dict[str, Any], Any]:
    sources = {
        "project.json": request.project_plan,
        "standards.json": request.standards_plan,
        "technologies.json": request.technologies_plan,
        "authority.json": request.authority_plan,
    }
    plans = {
        filename: load_json_strict(path, root=Path(path).parent)
        for filename, path in sources.items()
    }
    plans["project.json"] = compile_project_init(plans["project.json"], bundle)
    licenses = load_json_strict(request.licenses_plan, root=request.licenses_plan.parent)
    return plans, licenses


def _activation_identity(
    bundle: ContractBundle, plans: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "record_type": "Activation",
        "canonical_name": "promin",
        "core_bundle_digest": bundle.bundle_digest,
        "preset_digest": bundle.preset_digest,
        "init_file_digests": {
            filename: digest_value(plans[filename]) for filename in PLAN_FILES
        },
        "operating_profile": plans["project.json"]["operating_profile"],
        "trust_mode": plans["authority.json"]["trust_mode"],
        "implementation_closure_digest": implementation_closure_digest(
            plans["technologies.json"]
        ),
    }


def _verify_team_proofs(
    activation: Mapping[str, Any],
    authority: Mapping[str, Any],
    signature_verifier: SignatureVerifier | None,
) -> None:
    if signature_verifier is None:
        raise InitError("team-signed Activation requires a cryptographic signature verifier")
    keys = {item["key_id"]: item for item in authority["keys"]}
    allowed = set(authority["team_policy"]["key_ids"])
    accepted: set[str] = set()
    for proof in activation["proofs"]:
        key = keys.get(proof.get("key_id"))
        if (
            proof.get("kind") != "signature"
            or key is None
            or proof["key_id"] not in allowed
            or proof.get("algorithm") != key["algorithm"]
            or proof.get("signed_digest") != activation["activation_digest"]
            or proof["key_id"] in accepted
        ):
            raise InitError("invalid or duplicate team Activation proof")
        try:
            verified = signature_verifier(proof, key)
        except Exception as exc:
            raise InitError(f"signature verifier failed closed: {exc}") from exc
        if not verified:
            raise InitError(f"invalid Activation signature for key {proof['key_id']}")
        accepted.add(proof["key_id"])
    if len(accepted) < authority["team_policy"]["threshold"]:
        raise InitError("team Activation signature threshold is not satisfied")


def _make_activation(
    bundle: ContractBundle,
    plans: Mapping[str, Any],
    proofs: Sequence[Mapping[str, Any]] | None,
    signature_verifier: SignatureVerifier | None,
) -> dict[str, Any]:
    identity = _activation_identity(bundle, plans)
    activation_digest = digest_value(identity)
    authority = plans["authority.json"]
    if authority["trust_mode"] == "local-owner":
        if proofs is not None:
            raise InitError("local-owner Activation proof is derived from the explicit authority plan")
        root = authority["roots"][0]
        selected_proofs: list[Mapping[str, Any]] = [
            {
                "kind": "local-root",
                "subject_id": root["subject_id"],
                "authority_init_digest": identity["init_file_digests"]["authority.json"],
            }
        ]
    else:
        if not proofs:
            raise InitError("team-signed Activation requires explicit signature proofs")
        selected_proofs = list(proofs)
    activation = {
        **identity,
        "activation_digest": activation_digest,
        "proofs": selected_proofs,
    }
    validate_definition(bundle.schema, "Activation", activation)
    _verify_activation_proofs(activation, plans, signature_verifier)
    return activation


def _verify_activation_proofs(
    activation: Mapping[str, Any],
    plans: Mapping[str, Any],
    signature_verifier: SignatureVerifier | None,
) -> None:
    authority = plans["authority.json"]
    if activation["trust_mode"] != authority["trust_mode"]:
        raise InitError("Activation trust mode does not match authority init")
    if authority["trust_mode"] == "local-owner":
        roots = {item["subject_id"] for item in authority["roots"]}
        proofs = activation["proofs"]
        if len(proofs) != 1:
            raise InitError("local-owner Activation requires exactly one root proof")
        proof = proofs[0]
        if (
            proof.get("kind") != "local-root"
            or proof.get("subject_id") not in roots
            or proof.get("authority_init_digest")
            != activation["init_file_digests"]["authority.json"]
        ):
            raise InitError("invalid local-owner Activation proof")
    else:
        _verify_team_proofs(activation, authority, signature_verifier)


def _provider_verifiers(
    overrides: Mapping[str, ProviderVerifier] | None,
) -> dict[str, ProviderVerifier]:
    result = dict(DEFAULT_PROVIDER_VERIFIERS)
    if overrides:
        result.update(overrides)
    return result


def _matching_provider_source(
    binding: Mapping[str, Any], project_root: Path, invocation_value: str
) -> Path:
    source = _init_identity_path(str(binding["identity"]["source"]), project_root)
    invoked = _init_identity_path(invocation_value, project_root)
    if source != invoked:
        if (
            os.name == "nt"
            and binding.get("capability_id") == "filesystem-inventory"
            and invoked.name.casefold() == "git.exe"
        ):
            primary = next(
                (
                    item
                    for item in binding["dependency_receipt"]["components"]
                    if item["component_kind"] == "provider-file"
                    and item["digest"] == binding["identity"]["digest"]
                ),
                None,
            )
            if primary is not None and invoked == _init_identity_path(
                str(primary["source"]), project_root
            ):
                return invoked
        raise InitError(
            f"provider invocation does not match its identity: {binding['provider_id']}"
        )
    return source


def _python_module_signature_verifier(
    binding: Mapping[str, Any], project_root: Path
) -> SignatureVerifier:
    invocation_value = str(binding["invocation"]["value"])
    module_value, separator, callable_name = invocation_value.rpartition("#")
    if not separator or callable_name != "verify_signature" or not module_value:
        raise InitError(
            "python-module signature invocation must be '<module-file>#verify_signature'"
        )
    source = _matching_provider_source(binding, project_root, module_value)
    module_name = f"_promin_signature_{binding['identity']['digest']}"
    try:
        source_bytes = source.read_bytes()
        if len(source_bytes) > 1024 * 1024:
            raise InitError(
                f"signature provider module exceeds 1 MiB: {binding['provider_id']}"
            )
        if hashlib.sha256(source_bytes).hexdigest() != binding["identity"]["digest"]:
            raise InitError(f"provider digest drift: {binding['provider_id']}")
        namespace: dict[str, Any] = {
            "__name__": module_name,
            "__file__": str(source),
            "__package__": None,
        }
        exec(compile(source_bytes, str(source), "exec"), namespace)
    except InitError:
        raise
    except Exception as exc:
        raise InitError(
            f"signature provider module failed to load: {binding['provider_id']}: {exc}"
        ) from exc
    verify = namespace.get(callable_name)
    if not callable(verify):
        raise InitError(
            f"signature provider module lacks verify_signature: {binding['provider_id']}"
        )

    def invoke(proof: Mapping[str, Any], key: Mapping[str, Any]) -> bool:
        try:
            result = verify(dict(proof), dict(key))
        except Exception as exc:
            raise InitError(
                f"signature provider invocation failed: {binding['provider_id']}: {exc}"
            ) from exc
        if not isinstance(result, bool):
            raise InitError(
                f"signature provider returned a non-boolean result: {binding['provider_id']}"
            )
        return result

    return invoke


def _executable_signature_verifier(
    binding: Mapping[str, Any], project_root: Path
) -> SignatureVerifier:
    executable = _matching_provider_source(
        binding, project_root, str(binding["invocation"]["value"])
    )
    timeout = _provider_timeout_seconds(binding)

    def invoke(proof: Mapping[str, Any], key: Mapping[str, Any]) -> bool:
        request = {
            "operation": "verify-signature-v1",
            "proof": dict(proof),
            "key": dict(key),
        }
        try:
            completed = _run_identity_process(
                [str(executable), "--promin-signature-verify-v1"],
                cwd=project_root,
                input=canonical_bytes(request),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise InitError(
                f"signature provider invocation unavailable: {binding['provider_id']}: {exc}"
            ) from exc
        if completed.returncode != 0:
            raise InitError(
                f"signature provider invocation failed: {binding['provider_id']}: "
                f"exit={completed.returncode}"
            )
        try:
            response = parse_json_strict(completed.stdout)
        except Exception as exc:
            raise InitError(
                f"signature provider returned invalid canonical JSON: {binding['provider_id']}"
            ) from exc
        if (
            not isinstance(response, dict)
            or set(response) != {"verified"}
            or not isinstance(response["verified"], bool)
            or canonical_bytes(response) != completed.stdout
        ):
            raise InitError(
                f"signature provider returned an invalid response: {binding['provider_id']}"
            )
        return response["verified"]

    return invoke


def _verify_configured_healthcheck_paths_available(
    binding: Mapping[str, Any], project_root: Path
) -> None:
    """Verify source-side healthcheck executables before receipt installation.

    Installed/restarted projects intentionally run from content-addressed
    receipts and must not depend on the original mutable source still existing.
    """

    healthcheck = binding.get("healthcheck")
    invocation = binding.get("invocation")
    if not isinstance(healthcheck, Mapping) or not isinstance(invocation, Mapping):
        raise InitError(f"invalid provider binding: {binding.get('provider_id')}")
    argv = healthcheck.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) for item in argv):
        raise InitError(f"provider healthcheck is invalid: {binding.get('provider_id')}")
    _init_identity_path(argv[0], project_root)
    if invocation.get("kind") == "python-module":
        if len(argv) < 2:
            raise InitError(
                f"provider healthcheck does not execute its bound interpreter and module: {binding.get('provider_id')}"
            )
        _init_identity_path(argv[1], project_root)


def resolve_provider_dispatch(
    technologies: Mapping[str, Any],
    project_root: Path,
    provider_verifiers: Mapping[str, ProviderVerifier] | None = None,
    *,
    contract_bundle: ContractBundle | None = None,
    receipt_root: Path | None = None,
    signature_verifier: SignatureVerifier | None = None,
    verify_implementation: bool = True,
    require_configured_healthcheck_paths: bool = False,
) -> ProviderDispatch:
    """Resolve every declared binding to one supported runtime implementation."""

    if technologies.get("record_type") != "TechnologiesInit" or not isinstance(
        technologies.get("bindings"), list
    ):
        raise InitError("provider dispatch requires a TechnologiesInit record")
    if signature_verifier is not None:
        raise InitError("process-local signature adapters are not reconstructable")
    bundle = contract_bundle or _canonical_runtime_bundle()
    protocols = provider_protocol_table(bundle)
    if receipt_root is None:
        verify_provider_identities(technologies, project_root, provider_verifiers)
    bindings: dict[str, Mapping[str, Any]] = {}
    adapters: dict[str, ProviderAdapter] = {}
    selected_signature: SignatureVerifier | None = None
    for source_binding in technologies["bindings"]:
        if require_configured_healthcheck_paths:
            _verify_configured_healthcheck_paths_available(source_binding, project_root)
        # Reject an unsupported capability/adapter tuple before validating its
        # implementation receipt.  This produces the correct failure boundary
        # and prevents stale receipts from obscuring a configuration error.
        capability = source_binding.get("capability_id")
        provider_id = source_binding.get("provider_id")
        protocol = protocols.get(str(capability))
        if protocol is None:
            raise InitError(f"unsupported provider capability: {capability}")
        if capability in bindings:
            raise InitError(f"duplicate provider capability binding: {capability}")
        if not isinstance(provider_id, str) or not provider_id:
            raise InitError("provider binding has no valid provider_id")
        invocation = source_binding.get("invocation")
        identity = source_binding.get("identity")
        dependency_receipt = source_binding.get("dependency_receipt")
        if (
            not isinstance(invocation, Mapping)
            or not isinstance(identity, Mapping)
            or not isinstance(dependency_receipt, Mapping)
        ):
            raise InitError(f"invalid provider binding: {provider_id}")
        invocation_kind = invocation.get("kind")
        identity_kind = identity.get("kind")
        adapter_id = protocol.supported_bindings.get(
            (str(invocation_kind), str(identity_kind))
        )
        if adapter_id is None:
            raise InitError(
                f"unsupported provider adapter: capability={capability} "
                f"invocation={invocation_kind} identity={identity_kind}"
            )
        if adapter_id not in _IMPLEMENTED_PROVIDER_ADAPTERS:
            raise InitError(
                f"provider adapter has no runtime invocation hook: {capability}: {adapter_id}"
            )
        if receipt_root is None:
            verify_provider_dependency_receipt(source_binding, project_root)
        binding = _runtime_provider_binding(source_binding, project_root, receipt_root)
        invocation = binding["invocation"]
        identity = binding["identity"]
        dependency_receipt = binding["dependency_receipt"]
        persistence_scope = (
            protocol.receipt_persistence if receipt_root is not None else "technology-binding"
        )

        if invocation_kind == "python-module":
            invocation_value = str(invocation["value"])
            module_value, separator, callable_name = invocation_value.rpartition("#")
            if not separator or not callable_name:
                raise InitError(f"provider module invocation is not explicit: {provider_id}")
            _matching_provider_source(binding, project_root, module_value)
            if capability == "signature":
                if callable_name != "verify_signature":
                    raise InitError(
                        "python-module signature invocation must bind verify_signature"
                    )
                selected_signature = _python_module_signature_verifier(
                    binding, project_root
                )
        elif invocation_kind in {"python-runtime", "executable"}:
            _matching_provider_source(binding, project_root, str(invocation["value"]))
            if capability == "signature":
                if invocation_kind != "executable":
                    raise InitError(
                        "signature provider must use a reconstructable Core protocol"
                    )
                selected_signature = _executable_signature_verifier(
                    binding, project_root
                )
        else:
            raise InitError(
                f"unsupported provider invocation protocol: capability={capability} "
                f"invocation={invocation_kind}"
            )

        bindings[capability] = binding
        adapters[capability] = ProviderAdapter(
            capability_id=capability,
            provider_id=provider_id,
            invocation_kind=str(invocation_kind),
            identity_kind=str(identity_kind),
            identity_digest=str(identity["digest"]),
            adapter_id=adapter_id,
            persistence_scope=persistence_scope,
            reconstructable=True,
            protocol_id=protocol.protocol_id,
            supported_operations=tuple(protocol.operation_contracts),
            operation_contract_digest=digest_value(protocol.operation_contracts),
            operation_contract_digests={
                operation: digest_value(contract)
                for operation, contract in protocol.operation_contracts.items()
            },
            dependency_receipt_digest=str(dependency_receipt["aggregate_digest"]),
        )
    if selected_signature is not None:
        unbound_signature = selected_signature

        def bound_signature(
            proof: Mapping[str, Any], key: Mapping[str, Any]
        ) -> bool:
            return unbound_signature(proof, key)

        setattr(
            bound_signature,
            "provider_evidence",
            adapters["signature"].binding_evidence(),
        )
        selected_signature = bound_signature
    dispatch = ProviderDispatch(
        bindings,
        adapters,
        {capability: protocols[capability] for capability in bindings},
        project_root,
        selected_signature,
        _provider_evidence_limits(bundle),
    )
    if verify_implementation:
        verify_implementation_closures(technologies, dispatch)
    return dispatch


def verify_provider_identities(
    technologies: Mapping[str, Any],
    project_root: Path,
    verifiers: Mapping[str, ProviderVerifier] | None = None,
) -> None:
    available = _provider_verifiers(verifiers)
    for binding in technologies["bindings"]:
        identity = binding["identity"]
        verifier = available.get(identity["kind"])
        if verifier is None:
            raise InitError(
                f"provider identity kind requires an explicit verifier: {identity['kind']}"
            )
        try:
            actual = verifier(identity, project_root)
        except ContractError:
            raise
        except Exception as exc:
            raise InitError(
                f"provider identity verification failed for {binding['provider_id']}: {exc}"
            ) from exc
        if actual != identity["digest"]:
            raise InitError(f"provider digest mismatch: {binding['provider_id']}")


def _utc_second_text() -> str:
    return format_utc_second(datetime.now(timezone.utc).replace(microsecond=0))


def _provider_health_observation(
    dispatch: ProviderDispatch,
    capability_id: str,
    binding: Mapping[str, Any],
    argv: Sequence[str],
    project_root: Path,
    *,
    started_at: str,
    completed_at: str,
    exit_code: int,
    stdout: bytes,
    stderr: bytes,
) -> dict[str, Any]:
    adapter = dispatch.adapter(capability_id)
    invocation_receipt = {
        "record_type": "ProviderHealthInvocationReceipt",
        "protocol_id": adapter.protocol_id,
        "operation": "healthcheck",
        "provider_id": adapter.provider_id,
        "argv": list(argv),
        "cwd": str(project_root),
        "stdin": "none",
        "timeout_ms": binding["healthcheck"]["timeout_ms"],
        "expected_exit": binding["healthcheck"]["expected_exit"],
        "identity_digest": adapter.identity_digest,
        "dependency_receipt_digest": adapter.dependency_receipt_digest,
        "persistence_scope": adapter.persistence_scope,
    }
    return {
        **adapter.invocation_evidence("healthcheck"),
        "invocation_receipt_digest": digest_value(invocation_receipt),
        "persistence_scope": adapter.persistence_scope,
        "reconstructable": adapter.reconstructable,
        "invoked": True,
        "started_at": started_at,
        "completed_at": completed_at,
        "outcome": "healthy",
        "exit_code": exit_code,
        "stdout_digest": hashlib.sha256(stdout).hexdigest(),
        "stdout_size_bytes": len(stdout),
        "stderr_digest": hashlib.sha256(stderr).hexdigest(),
        "stderr_size_bytes": len(stderr),
        "authoritative": False,
        "pass_credit": False,
    }


def verify_provider_preflight(
    technologies: Mapping[str, Any],
    project_root: Path,
    *,
    contract_bundle: ContractBundle | None = None,
    provider_dispatch: ProviderDispatch | None = None,
    receipt_root: Path | None = None,
) -> tuple[dict[str, Any], ...]:
    if receipt_root is None:
        installed_receipts = project_root / ".promin" / "providers"
        if installed_receipts.is_dir() and not installed_receipts.is_symlink():
            receipt_root = installed_receipts
    if contract_bundle is None and receipt_root is not None:
        control = project_root / ".promin"
        init_dir = control / "init"
        activation = load_json_strict(init_dir / "activation.json", root=init_dir)
        bundle_digest = activation.get("core_bundle_digest")
        preset_digest = activation.get("preset_digest")
        if not isinstance(bundle_digest, str) or not isinstance(preset_digest, str):
            raise InitError("installed provider preflight lacks Activation identities")
        installed = control / "standard" / bundle_digest
        contract_bundle = load_contract_bundle(
            installed, installed / "presets" / f"{preset_digest}.json"
        )
    dispatch_input = (
        technologies
        if technologies.get("record_type") == "TechnologiesInit"
        else {"record_type": "TechnologiesInit", "bindings": technologies.get("bindings")}
    )
    dispatch = provider_dispatch or resolve_provider_dispatch(
        dispatch_input,
        project_root,
        contract_bundle=contract_bundle,
        receipt_root=receipt_root,
        verify_implementation=False,
    )
    observations: list[dict[str, Any]] = []
    for source_binding in dispatch_input["bindings"]:
        capability_id = str(source_binding["capability_id"])
        binding = dispatch.binding(capability_id)
        identity = binding["identity"]
        invocation = binding["invocation"]
        healthcheck = binding["healthcheck"]
        argv = list(healthcheck["argv"])
        if not argv:
            raise InitError(f"provider healthcheck has no argv: {binding['provider_id']}")
        invocation_kind = invocation["kind"]
        if invocation_kind in {"python-runtime", "executable"}:
            source = _matching_provider_source(
                binding, project_root, str(invocation["value"])
            )
            checked = _init_identity_path(str(argv[0]), project_root)
            if source != checked:
                raise InitError(
                    f"provider healthcheck does not execute its bound identity: {binding['provider_id']}"
                )
        elif invocation_kind == "python-module":
            module_value, separator, callable_name = str(invocation["value"]).rpartition(
                "#"
            )
            if not separator or not callable_name:
                raise InitError(
                    f"provider module invocation is not explicit: {binding['provider_id']}"
                )
            source = _matching_provider_source(binding, project_root, module_value)
            checked_interpreter = _init_identity_path(str(argv[0]), project_root)
            interpreter_component = next(
                (
                    component
                    for component in binding["dependency_receipt"]["components"]
                    if component["component_id"] == "interpreter"
                ),
                None,
            )
            if interpreter_component is None:
                raise InitError("Python provider dependency receipt lacks its interpreter")
            if receipt_root is None:
                expected_interpreter = _init_identity_path(
                    str(interpreter_component["source"]), project_root
                )
                if checked_interpreter != expected_interpreter:
                    raise InitError(
                        f"provider module healthcheck interpreter is not exact: {binding['provider_id']}"
                    )
            elif (
                not checked_interpreter.is_relative_to(resolve_identity_path(receipt_root, strict=True))
                or digest_file(checked_interpreter) != interpreter_component["digest"]
            ):
                raise InitError(
                    f"provider module receipt interpreter is not exact: {binding['provider_id']}"
                )
            if len(argv) < 2 or _init_identity_path(str(argv[1]), project_root) != source:
                raise InitError(
                    f"provider healthcheck does not execute its bound module: {binding['provider_id']}"
                )
        else:
            raise InitError(
                f"unsupported provider healthcheck adapter: {binding['provider_id']}: "
                f"{invocation_kind}"
            )
        interpreter_digest = (
            digest_file(checked_interpreter)
            if invocation_kind == "python-module"
            else None
        )
        adapter = dispatch.adapter(capability_id)
        provider_environment = (
            _git_receipt_environment(binding)
            if adapter.adapter_id == "git-executable-v1"
            and receipt_root is not None
            else None
        )
        started_at = _utc_second_text()
        spawn_argv = _spawn_provider_argv(binding, argv, project_root)
        expected_git_argv: list[str] | None = None
        if adapter.adapter_id == "git-executable-v1":
            expected_git_argv = [
                str(_init_identity_path(str(invocation["value"]), project_root)),
                "--version",
            ]
        try:
            completed = _run_identity_process(
                spawn_argv,
                cwd=project_root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=_provider_timeout_seconds(binding),
                check=False,
                shell=False,
                env=provider_environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise InitError(
                f"provider healthcheck unavailable: {binding['provider_id']}: {exc}"
            ) from exc
        completed_at = _utc_second_text()
        # A project receipt intentionally contains the exact provider payload,
        # but a Windows executable receipt is not necessarily a relocatable
        # application.  Git, for example, depends on installation-owned DLLs
        # outside its executable and provider-tree receipts.  Preserve the
        # receipt-first check, then fall back only when the original bound
        # source is still independently digest-verified.  This is not a
        # success substitute: an unavailable or changed source leaves the
        # receipt failure in force.
        if (
            completed.returncode != healthcheck["expected_exit"]
            and os.name == "nt"
            and receipt_root is not None
        ):
            try:
                # A receipt is a byte-exact integrity artifact, not proof that
                # an executable can be relocated without its installed DLL
                # neighbourhood.  The Windows fallback therefore first proves
                # every original provider identity again; it never turns a
                # receipt failure into success from an unchecked host binary.
                verify_provider_identities(dispatch_input, project_root)
                source_dispatch = resolve_provider_dispatch(
                    dispatch_input,
                    project_root,
                    contract_bundle=contract_bundle,
                    verify_implementation=False,
                )
                source_runtime = source_dispatch.binding(capability_id)
                source_argv = list(source_runtime["healthcheck"]["argv"])
                _source_spawn = _spawn_provider_argv(source_runtime, source_argv, project_root)
                source_completed = _run_identity_process(
                    _source_spawn,
                    cwd=project_root,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=_provider_timeout_seconds(source_runtime),
                    check=False,
                    shell=False,
                    env=None,
                )
            except (InitError, OSError, subprocess.TimeoutExpired):
                source_completed = None
            if (
                source_completed is not None
                and source_completed.returncode == healthcheck["expected_exit"]
            ):
                argv = source_argv
                completed = source_completed
                completed_at = _utc_second_text()
                if adapter.adapter_id == "git-executable-v1":
                    expected_git_argv = [
                        str(
                            _init_identity_path(
                                str(source_runtime["invocation"]["value"]), project_root
                            )
                        ),
                        "--version",
                    ]
        if interpreter_digest is not None and digest_file(checked_interpreter) != interpreter_digest:
            raise InitError(
                f"provider module interpreter changed during preflight: {binding['provider_id']}"
            )
        if completed.returncode != healthcheck["expected_exit"]:
            raise InitError(
                f"provider healthcheck failed: {binding['provider_id']}: "
                f"expected={healthcheck['expected_exit']} actual={completed.returncode}"
            )
        if len(completed.stdout) > 64 * 1024 or len(completed.stderr) > 64 * 1024:
            raise InitError(
                f"provider healthcheck output exceeds its bound: {binding['provider_id']}"
            )
        if adapter.adapter_id == "git-executable-v1":
            if argv != expected_git_argv:
                raise InitError("Git provider healthcheck argv is not the exact Core protocol")
            if not re.fullmatch(rb"git version [ -~]{1,256}\r?\n", completed.stdout):
                raise InitError("Git provider healthcheck response is not exact")
        observation = _provider_health_observation(
            dispatch,
            capability_id,
            binding,
            argv,
            project_root,
            started_at=started_at,
            completed_at=completed_at,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        dispatch._record_health_observation(capability_id, observation)
        observations.append(observation)
    return tuple(observations)


def _copy_regular(source: Path, destination: Path, *, root: Path) -> None:
    resolved = require_regular_file(source, root=root)
    _make_directory(destination.parent, parents=True, exist_ok=True)
    try:
        with resolved.open("rb") as reader, open(_native_path(destination), "xb") as writer:
            for chunk in iter(lambda: reader.read(1024 * 1024), b""):
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
    except OSError as exc:
        raise InitError(f"cannot install standard artifact {source.name}: {exc}") from exc


def _install_bundle(staging_control: Path, bundle: ContractBundle) -> Path:
    installed = staging_control / "standard" / bundle.bundle_digest
    target_core = installed / "core"
    target_preset = installed / "presets" / f"{bundle.preset_digest}.json"
    _make_directory(target_core, parents=True)
    for filename in CORE_FILES:
        _copy_regular(
            bundle.core_dir / filename,
            target_core / filename,
            root=bundle.core_dir,
        )
    _make_directory(target_preset.parent, parents=True)
    _copy_regular(bundle.preset_path, target_preset, root=bundle.preset_path.parent)
    installed_bundle = load_contract_bundle(installed, _extended_path(target_preset))
    if (
        installed_bundle.bundle_digest != bundle.bundle_digest
        or installed_bundle.preset_digest != bundle.preset_digest
    ):
        raise InitError("installed standard does not preserve source identities")
    return installed


def _write_init(staging_control: Path, plans: Mapping[str, Any], activation: Mapping[str, Any]) -> None:
    init_dir = staging_control / "init"
    _make_directory(init_dir, parents=True)
    for filename in PLAN_FILES:
        target = init_dir / filename
        with open(_native_path(target), "xb") as handle:
            handle.write(canonical_bytes(plans[filename]))
            handle.flush()
            os.fsync(handle.fileno())
    activation_path = init_dir / "activation.json"
    with open(_native_path(activation_path), "xb") as handle:
        handle.write(canonical_bytes(activation))
        handle.flush()
        os.fsync(handle.fileno())
    ensure_exact_regular_files(init_dir, INIT_FILES)
    fsync_directory(init_dir)


def _write_continuation_secret(staging_control: Path, activation_digest: str) -> None:
    secrets = staging_control / "state" / "secrets"
    _make_directory(secrets, mode=0o700, parents=True, exist_ok=False)
    if os.name != "nt":
        os.chmod(secrets, 0o700)
    target = secrets / f"{activation_digest}.continuation.key"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(_native_path(target), flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(os.urandom(_CONTINUATION_SECRET_BYTES))
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    os.chmod(_native_path(target), 0o600)
    fsync_directory(secrets)
    fsync_directory(secrets.parent)


def _load_continuation_secret(control: Path, activation_digest: str) -> bytes:
    secrets = control / "state" / "secrets"
    try:
        directory_mode = os.stat(
            filesystem_path(secrets), follow_symlinks=False
        ).st_mode
    except OSError as exc:
        raise InitError(f"continuation secret directory is unavailable: {exc}") from exc
    if os.path.islink(filesystem_path(secrets)) or not stat.S_ISDIR(directory_mode):
        raise InitError("continuation secret directory must be a real directory")
    filename = f"{activation_digest}.continuation.key"
    (target,) = ensure_exact_regular_files(secrets, (filename,))
    try:
        mode = os.stat(filesystem_path(target), follow_symlinks=False).st_mode
        with open(_native_path(target), "rb") as handle:
            secret = handle.read(_CONTINUATION_SECRET_BYTES + 1)
    except OSError as exc:
        raise InitError(f"continuation secret is unavailable: {exc}") from exc
    if len(secret) != _CONTINUATION_SECRET_BYTES:
        raise InitError("continuation secret has an invalid size")
    if os.name != "nt" and stat.S_IMODE(mode) & (stat.S_IRWXG | stat.S_IRWXO):
        raise InitError("continuation secret permissions are not restrictive")
    if os.name != "nt" and stat.S_IMODE(directory_mode) & (stat.S_IRWXG | stat.S_IRWXO):
        raise InitError("continuation secret directory permissions are not restrictive")
    return secret


def _make_runtime_directories(staging_control: Path, activation_digest: str) -> None:
    for relative in (
        "state/events/batches",
        "state/objects/sha256",
        "state/projection",
        "state/locks",
        "generated",
        "cache",
    ):
        _make_directory(staging_control / relative, parents=True, exist_ok=False)
    _write_continuation_secret(staging_control, activation_digest)


def _set_installed_read_only(installed: Path, *, preserve_execute: bool = False) -> None:
    for directory, _, filenames in os.walk(installed, topdown=False, followlinks=False):
        base = Path(directory)
        for filename in filenames:
            path = base / filename
            if os.path.islink(filesystem_path(path)):
                raise InitError(f"installed standard contains a symbolic link: {path}")
            executable_bits = (
                os.stat(filesystem_path(path), follow_symlinks=False).st_mode
                & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                if preserve_execute
                else 0
            )
            os.chmod(_native_path(path), stat.S_IREAD | executable_bits)
        os.chmod(_native_path(base), stat.S_IREAD | stat.S_IEXEC)


def _remove_staging(path: Path) -> None:
    if not os.path.lexists(_native_path(path)):
        return
    native_root = _extended_path(path)
    for directory, directories, filenames in os.walk(native_root, topdown=False):
        for filename in filenames:
            try:
                os.chmod(Path(directory) / filename, stat.S_IWRITE | stat.S_IREAD)
            except OSError:
                pass
        for name in directories:
            try:
                os.chmod(Path(directory) / name, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            except OSError:
                pass
    shutil.rmtree(native_root, ignore_errors=False)


def _publish_control_directory(staging: Path, control: Path) -> None:
    """Publish one fully verified control tree with a bounded Windows lock retry."""

    for attempt in range(8):
        try:
            os.rename(_native_path(staging), _native_path(control))
            return
        except PermissionError:
            if attempt == 7:
                raise
            time.sleep(0.05 * (attempt + 1))


class ActivationGuard:
    def __init__(
        self,
        project_root: str | Path,
        *,
        provider_verifiers: Mapping[str, ProviderVerifier] | None = None,
        signature_verifier: SignatureVerifier | None = None,
    ) -> None:
        supplied_root = Path(project_root)
        if supplied_root.is_symlink():
            raise InitError("project root symbolic link rejected")
        self.project_root = resolve_identity_path(supplied_root, strict=True)
        self.provider_verifiers = provider_verifiers or {}
        self.signature_verifier = signature_verifier

    def verify(self, *, verify_schema_meta: bool = True) -> ActivationContext:
        control = self.project_root / ".promin"
        try:
            mode = os.stat(filesystem_path(control), follow_symlinks=False).st_mode
        except OSError as exc:
            raise InitError(f"Promin control state is unavailable: {exc}") from exc
        if os.path.islink(filesystem_path(control)) or not stat.S_ISDIR(mode):
            raise InitError(".promin must be a real directory")
        init_dir = control / "init"
        ensure_exact_regular_files(init_dir, INIT_FILES)
        records = {
            filename: load_json_strict(init_dir / filename, root=init_dir)
            for filename in INIT_FILES
        }
        activation = records["activation.json"]
        if not isinstance(activation, dict) or activation.get("canonical_name") != "promin":
            raise InitError("invalid Promin Activation identity")
        bundle_digest = activation.get("core_bundle_digest")
        preset_digest = activation.get("preset_digest")
        if not isinstance(bundle_digest, str) or not isinstance(preset_digest, str):
            raise InitError("Activation is missing installed standard identities")
        installed = control / "standard" / bundle_digest
        preset_path = installed / "presets" / f"{preset_digest}.json"
        bundle = load_contract_bundle(
            installed,
            _extended_path(preset_path),
            verify_schema_meta=verify_schema_meta,
        )
        validate_definition(bundle.schema, "Activation", activation)
        plans = {filename: records[filename] for filename in PLAN_FILES}
        for filename, definition in {
            "project.json": "ProjectInit",
            "standards.json": "StandardsInit",
            "technologies.json": "TechnologiesInit",
            "authority.json": "AuthorityInit",
        }.items():
            validate_definition(bundle.schema, definition, plans[filename])
        verify_provider_receipt_inventory(
            plans["technologies.json"], control / "providers", self.project_root
        )
        expected_identity = _activation_identity(bundle, plans)
        for key, value in expected_identity.items():
            if activation.get(key) != value:
                raise InitError(f"Activation binding mismatch: {key}")
        if activation["activation_digest"] != digest_value(expected_identity):
            raise InitError("Activation digest mismatch")
        # Cross-record authority checks follow immutable Activation binding so a
        # tampered init file is reported as a binding failure rather than as an
        # incidental semantic mismatch.
        _validate_project_bound_authority(plans)
        licenses = {
            "record_type": "LicensesPlan",
            "bindings": [
                {"provider_id": item["provider_id"], "license": item["license"]}
                for item in plans["technologies.json"]["bindings"]
            ],
        }
        validate_plan_objects(plans, bundle, licenses)
        provider_dispatch = resolve_provider_dispatch(
            plans["technologies.json"],
            self.project_root,
            self.provider_verifiers,
            contract_bundle=bundle,
            receipt_root=control / "providers",
            signature_verifier=self.signature_verifier,
        )
        selected_verifier = (
            provider_dispatch.signature_verifier()
            if activation["trust_mode"] == "team-signed"
            else None
        )
        _verify_activation_proofs(activation, plans, selected_verifier)
        _load_continuation_secret(control, activation["activation_digest"])
        return ActivationContext(
            self.project_root,
            control,
            installed,
            bundle,
            plans,
            activation,
            provider_dispatch,
        )

    def verify_authoritative_mutation(self) -> ActivationContext:
        """Perform uncached full-byte verification for an authoritative mutation."""

        first = self.verify()
        first_digest = activation_byte_digest(first)
        second = self.verify()
        second_digest = activation_byte_digest(second)
        if (
            first.activation_digest != second.activation_digest
            or first_digest != second_digest
        ):
            raise InitError("Activation-bound bytes changed during mutation verification")
        return replace(second, authoritative_byte_digest=second_digest)


def verify_before_mutation(
    project_root: str | Path,
    *,
    provider_verifiers: Mapping[str, ProviderVerifier] | None = None,
    signature_verifier: SignatureVerifier | None = None,
) -> ActivationContext:
    return ActivationGuard(
        project_root,
        provider_verifiers=provider_verifiers,
        signature_verifier=signature_verifier,
    ).verify_authoritative_mutation()


def initialize_project(request: InitRequest) -> InitResult:
    supplied_root = Path(request.project_root)
    if supplied_root.is_symlink():
        raise InitError("project root symbolic link rejected")
    project_root = resolve_identity_path(supplied_root, strict=True)
    if not project_root.is_dir():
        raise InitError("project root must be a real existing directory")
    with _project_init_lock(project_root):
        return _initialize_project_locked(request, project_root)


def _initialize_project_locked(request: InitRequest, project_root: Path) -> InitResult:
    bundle = load_contract_bundle(request.standard_bundle, request.preset_path)
    plans, licenses = _load_plan_files(request, bundle)
    validate_plan_objects(plans, bundle, licenses)
    _validate_project_bound_authority(plans)
    control = project_root / ".promin"
    portable_shell_backup: Path | None = None
    if control.exists() and _is_portable_control_shell(control):
        portable_shell_backup = project_root / f".p-portable-{uuid.uuid4().hex[:12]}"
        os.rename(control, portable_shell_backup)
        fsync_directory(project_root)
    if control.exists() or control.is_symlink():
        context = ActivationGuard(
            project_root,
            provider_verifiers=request.provider_verifiers,
            signature_verifier=request.signature_verifier,
        ).verify()
        selected_verifier = (
            context.provider_dispatch.signature_verifier()
            if plans["authority.json"]["trust_mode"] == "team-signed"
            else None
        )
        activation = _make_activation(
            bundle,
            plans,
            request.activation_proofs,
            selected_verifier,
        )
        if context.plans != plans or context.activation != activation:
            raise InitError("existing Promin initialization differs from the requested content")
        _require_same_init_input_identity(
            _init_input_identity(
                bundle,
                plans,
                licenses,
                activation,
                project_root,
                provider_receipt_root=context.control_root / "providers",
            ),
            _init_input_identity(
                context.bundle,
                context.plans,
                licenses,
                context.activation,
                project_root,
                provider_receipt_root=context.control_root / "providers",
            ),
            boundary="idempotent initialization reuse",
        )
        observations = verify_provider_preflight(
            context.plans["technologies.json"],
            project_root,
            contract_bundle=context.bundle,
            provider_dispatch=context.provider_dispatch,
            receipt_root=context.control_root / "providers",
        )
        write_current_host_binding(context.control_root)
        return InitResult(
            context,
            created=False,
            preflight_receipt=_init_preflight_receipt(observations),
        )

    expected_activation, expected_identity, preflight_receipt = _preflight_init_inputs(
        request,
        project_root,
        bundle,
        plans,
        licenses,
    )
    source_dispatch = resolve_provider_dispatch(
        plans["technologies.json"],
        project_root,
        request.provider_verifiers,
        contract_bundle=bundle,
        signature_verifier=request.signature_verifier,
    )
    source_verifier = (
        source_dispatch.signature_verifier()
        if plans["authority.json"]["trust_mode"] == "team-signed"
        else None
    )
    source_activation = _make_activation(
        bundle,
        plans,
        request.activation_proofs,
        source_verifier,
    )
    if source_activation != expected_activation:
        raise InitError("Activation changed before project staging")
    _require_same_init_input_identity(
        expected_identity,
        _init_input_identity(
            bundle,
            plans,
            licenses,
            expected_activation,
            project_root,
            provider_receipt_root=None,
        ),
        boundary="project staging",
    )

    # Keep the non-authoritative staging component short enough for Windows
    # while retaining an unpredictable collision boundary.
    staging = project_root / f".p-{uuid.uuid4().hex[:12]}"
    try:
        _make_directory(staging)
        installed = _install_bundle(staging, bundle)
        receipt_root = staging / "providers"
        materialize_provider_receipts(
            plans["technologies.json"], project_root, receipt_root
        )
        verify_provider_receipt_inventory(
            plans["technologies.json"], receipt_root, project_root
        )
        provider_dispatch = resolve_provider_dispatch(
            plans["technologies.json"],
            project_root,
            request.provider_verifiers,
            contract_bundle=bundle,
            receipt_root=receipt_root,
            signature_verifier=request.signature_verifier,
        )
        verify_provider_preflight(
            plans["technologies.json"],
            project_root,
            contract_bundle=bundle,
            provider_dispatch=provider_dispatch,
            receipt_root=receipt_root,
        )
        selected_verifier = (
            provider_dispatch.signature_verifier()
            if plans["authority.json"]["trust_mode"] == "team-signed"
            else None
        )
        activation = _make_activation(
            bundle,
            plans,
            request.activation_proofs,
            selected_verifier,
        )
        if activation != expected_activation:
            raise InitError("Activation changed after pre-mutation verification")
        _write_init(staging, plans, activation)
        _make_runtime_directories(staging, activation["activation_digest"])
        write_current_host_binding(staging)
        if portable_shell_backup is not None:
            _merge_portable_control_shell(portable_shell_backup, staging)
        fsync_directory(staging)
        _require_same_init_input_identity(
            expected_identity,
            _staged_init_input_identity(
                staging,
                expected_identity,
                licenses,
                project_root,
            ),
            boundary="atomic initialization publication",
        )
        try:
            _publish_control_directory(staging, control)
        except OSError as exc:
            if control.exists():
                context = ActivationGuard(
                    project_root,
                    provider_verifiers=request.provider_verifiers,
                    signature_verifier=request.signature_verifier,
                ).verify()
                if context.plans == plans and context.activation == activation:
                    _require_same_init_input_identity(
                        expected_identity,
                        _init_input_identity(
                            context.bundle,
                            context.plans,
                            licenses,
                            context.activation,
                            project_root,
                            provider_receipt_root=context.control_root / "providers",
                        ),
                        boundary="concurrent initialization reuse",
                    )
                    observations = verify_provider_preflight(
                        context.plans["technologies.json"],
                        project_root,
                        contract_bundle=context.bundle,
                        provider_dispatch=context.provider_dispatch,
                        receipt_root=context.control_root / "providers",
                    )
                    write_current_host_binding(context.control_root)
                    _remove_staging(staging)
                    if portable_shell_backup is not None and portable_shell_backup.exists():
                        _merge_portable_control_shell(portable_shell_backup, control)
                        shutil.rmtree(portable_shell_backup)
                    return InitResult(
                        context,
                        created=False,
                        preflight_receipt=_init_preflight_receipt(observations),
                    )
                raise InitError(
                    "concurrent Promin initialization differs from the requested content"
                ) from exc
            raise InitError(f"cannot atomically install .promin: {exc}") from exc
        fsync_directory(project_root)
        _set_installed_read_only(control / "standard", preserve_execute=False)
        _set_installed_read_only(control / "providers", preserve_execute=True)
        fsync_directory(control)
        context = ActivationGuard(
            project_root,
            provider_verifiers=request.provider_verifiers,
            signature_verifier=request.signature_verifier,
        ).verify()
        if context.installed_standard != control / "standard" / bundle.bundle_digest:
            raise InitError("installed standard path changed during initialization")
        _require_same_init_input_identity(
            expected_identity,
            _init_input_identity(
                context.bundle,
                context.plans,
                licenses,
                context.activation,
                project_root,
                provider_receipt_root=context.control_root / "providers",
            ),
            boundary="initialized context return",
        )
        verify_provider_preflight(
            context.plans["technologies.json"],
            project_root,
            contract_bundle=context.bundle,
            provider_dispatch=context.provider_dispatch,
            receipt_root=context.control_root / "providers",
        )
        if portable_shell_backup is not None and portable_shell_backup.exists():
            shutil.rmtree(portable_shell_backup)
        return InitResult(
            context,
            created=True,
            preflight_receipt=preflight_receipt,
        )
    except BaseException:
        if staging.exists():
            _remove_staging(staging)
        raise
