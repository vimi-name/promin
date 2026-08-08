"""Typed writer identity and fail-closed process liveness classification.

This module deliberately does not acquire a filesystem lock.  A caller that
changes a control root must still hold its authoritative writer lock; this
module answers the narrower, auditable question of whether a persisted writer
record can be treated as inactive.  An unavailable process-birth observation
is never treated as permission to recover.
"""

from __future__ import annotations

import ctypes
import os
import re
import sys
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Mapping

from .canonical import digest_value


class WriterIdentityError(RuntimeError):
    """Raised when a writer record cannot safely participate in recovery."""


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
_BIRTH_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_WRITER_SCHEMA = "promin.writer-identity.v1"


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise WriterIdentityError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise WriterIdentityError(f"{label} is not a bounded writer identifier")
    return value


def _require_birth_token(value: object) -> str:
    if not isinstance(value, str) or _BIRTH_TOKEN.fullmatch(value) is None:
        raise WriterIdentityError("process_birth_token is invalid")
    return value


def _require_ns(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise WriterIdentityError(f"{label} must be a positive integer nanosecond value")
    return value


@dataclass(frozen=True, slots=True)
class WriterIdentity:
    """One writer bound to a process instance, activation, intent and lease.

    ``process_birth_token`` is intentionally stronger than a PID.  A matching
    PID with a different birth token means the original writer is gone and the
    PID has been reused; it must never be called live merely because its number
    still exists.
    """

    writer_id: str
    pid: int
    process_birth_token: str
    activation_digest: str
    intent_digest: str
    lease_started_ns: int
    lease_expires_ns: int

    def __post_init__(self) -> None:
        _require_identifier(self.writer_id, "writer_id")
        if not isinstance(self.pid, int) or isinstance(self.pid, bool) or self.pid < 1:
            raise WriterIdentityError("pid must be a positive integer")
        _require_birth_token(self.process_birth_token)
        _require_digest(self.activation_digest, "activation_digest")
        _require_digest(self.intent_digest, "intent_digest")
        started = _require_ns(self.lease_started_ns, "lease_started_ns")
        expires = _require_ns(self.lease_expires_ns, "lease_expires_ns")
        if expires <= started:
            raise WriterIdentityError("lease_expires_ns must be after lease_started_ns")

    def identity_payload(self) -> dict[str, object]:
        """Return the one canonical payload owned by this type."""

        return {
            "schema": _WRITER_SCHEMA,
            "record_type": "WriterIdentity",
            "writer_id": self.writer_id,
            "pid": self.pid,
            "process_birth_token": self.process_birth_token,
            "activation_digest": self.activation_digest,
            "intent_digest": self.intent_digest,
            "lease_started_ns": self.lease_started_ns,
            "lease_expires_ns": self.lease_expires_ns,
        }

    @property
    def identity_digest(self) -> str:
        return digest_value(self.identity_payload())

    def to_record(self) -> dict[str, object]:
        return {**self.identity_payload(), "identity_digest": self.identity_digest}

    @classmethod
    def from_record(cls, value: Mapping[str, object]) -> "WriterIdentity":
        if not isinstance(value, Mapping):
            raise WriterIdentityError("writer identity record must be an object")
        required = {
            "schema",
            "record_type",
            "writer_id",
            "pid",
            "process_birth_token",
            "activation_digest",
            "intent_digest",
            "lease_started_ns",
            "lease_expires_ns",
            "identity_digest",
        }
        if set(value) != required:
            raise WriterIdentityError("writer identity record has an inexact field set")
        if value["schema"] != _WRITER_SCHEMA or value["record_type"] != "WriterIdentity":
            raise WriterIdentityError("writer identity record type is invalid")
        identity = cls(
            writer_id=_require_identifier(value["writer_id"], "writer_id"),
            pid=value["pid"],  # type: ignore[arg-type]
            process_birth_token=_require_birth_token(value["process_birth_token"]),
            activation_digest=_require_digest(value["activation_digest"], "activation_digest"),
            intent_digest=_require_digest(value["intent_digest"], "intent_digest"),
            lease_started_ns=_require_ns(value["lease_started_ns"], "lease_started_ns"),
            lease_expires_ns=_require_ns(value["lease_expires_ns"], "lease_expires_ns"),
        )
        if value["identity_digest"] != identity.identity_digest:
            raise WriterIdentityError("writer identity digest does not bind its record")
        return identity


@dataclass(frozen=True, slots=True)
class ProcessObservation:
    """A bounded result from one process-instance inspection.

    ``exists=None`` represents an unavailable or denied observation, not a
    missing process.  This distinction is important because recovery may only
    proceed for evidence of absence, never for absence of evidence.
    """

    pid: int
    exists: bool | None
    process_birth_token: str | None = None
    inspection_error: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.pid, int) or isinstance(self.pid, bool) or self.pid < 1:
            raise WriterIdentityError("observed pid must be a positive integer")
        if self.exists is not True and self.exists is not False and self.exists is not None:
            raise WriterIdentityError("process observation existence is invalid")
        if self.process_birth_token is not None:
            _require_birth_token(self.process_birth_token)
        if self.exists is False and self.process_birth_token is not None:
            raise WriterIdentityError("missing process cannot have a birth token")
        if self.inspection_error is not None:
            if (
                not isinstance(self.inspection_error, str)
                or not self.inspection_error
                or len(self.inspection_error) > 160
            ):
                raise WriterIdentityError("inspection_error is invalid")


class WriterLiveness(str, Enum):
    """Whether a writer record permits recovery of the control root."""

    ABSENT = "ABSENT"
    LIVE = "LIVE"
    LEASE_EXPIRED = "LEASE_EXPIRED"
    INACTIVE = "INACTIVE"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True, slots=True)
class WriterLivenessReport:
    """A typed classification with an explicit recovery decision."""

    status: WriterLiveness
    reason: str
    writer_identity_digest: str | None
    observed_process_birth_token: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, WriterLiveness):
            raise WriterIdentityError("writer liveness status is invalid")
        if not isinstance(self.reason, str) or not self.reason or len(self.reason) > 160:
            raise WriterIdentityError("writer liveness reason is invalid")
        if self.writer_identity_digest is not None:
            _require_digest(self.writer_identity_digest, "writer_identity_digest")
        if self.observed_process_birth_token is not None:
            _require_birth_token(self.observed_process_birth_token)

    @property
    def recovery_permitted(self) -> bool:
        """True only when no live writer record remains to be respected."""

        return self.status in {WriterLiveness.ABSENT, WriterLiveness.INACTIVE}

    def to_record(self) -> dict[str, object]:
        return {
            "schema": "promin.writer-liveness.v1",
            "record_type": "WriterLiveness",
            "status": self.status.value,
            "reason": self.reason,
            "writer_identity_digest": self.writer_identity_digest,
            "observed_process_birth_token": self.observed_process_birth_token,
            "recovery_permitted": self.recovery_permitted,
        }


ProcessObserver = Callable[[int], ProcessObservation]


def _windows_process_observation(pid: int) -> ProcessObservation:
    from ctypes import wintypes

    class _FileTime(ctypes.Structure):
        _fields_ = (("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD))

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_process.restype = wintypes.HANDLE
    get_process_times = kernel32.GetProcessTimes
    get_process_times.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_FileTime),
        ctypes.POINTER(_FileTime),
        ctypes.POINTER(_FileTime),
        ctypes.POINTER(_FileTime),
    )
    get_process_times.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    process_query_limited_information = 0x1000
    handle = open_process(process_query_limited_information, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        if error in {87, 1168}:  # ERROR_INVALID_PARAMETER / ERROR_NOT_FOUND
            return ProcessObservation(pid=pid, exists=False)
        return ProcessObservation(
            pid=pid,
            exists=None,
            inspection_error=f"windows-open-process:{error}",
        )
    try:
        created = _FileTime()
        exited = _FileTime()
        kernel = _FileTime()
        user = _FileTime()
        if not get_process_times(handle, created, exited, kernel, user):
            return ProcessObservation(
                pid=pid,
                exists=None,
                inspection_error=f"windows-get-process-times:{ctypes.get_last_error()}",
            )
        creation_value = (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)
        return ProcessObservation(
            pid=pid,
            exists=True,
            process_birth_token=f"windows-filetime:{creation_value}",
        )
    finally:
        close_handle(handle)


def _linux_process_observation(pid: int) -> ProcessObservation:
    stat_path = f"/proc/{pid}/stat"
    try:
        with open(stat_path, "rt", encoding="utf-8") as stream:
            raw_stat = stream.read()
    except FileNotFoundError:
        return ProcessObservation(pid=pid, exists=False)
    except PermissionError:
        return ProcessObservation(pid=pid, exists=None, inspection_error="linux-proc-denied")
    except OSError as exc:
        return ProcessObservation(
            pid=pid,
            exists=None,
            inspection_error=f"linux-proc-unavailable:{getattr(exc, 'errno', 'unknown')}",
        )
    closing = raw_stat.rfind(")")
    fields = raw_stat[closing + 2 :].split() if closing >= 0 else ()
    # Fields after the command begin at field 3; field 22 (starttime) is index 19.
    if len(fields) <= 19 or not fields[19].isdigit():
        return ProcessObservation(pid=pid, exists=None, inspection_error="linux-proc-malformed")
    try:
        with open("/proc/sys/kernel/random/boot_id", "rt", encoding="ascii") as stream:
            boot_id = stream.read().strip().lower()
    except (OSError, UnicodeError):
        return ProcessObservation(pid=pid, exists=None, inspection_error="linux-boot-id-unavailable")
    if not re.fullmatch(r"[0-9a-f-]{36}", boot_id):
        return ProcessObservation(pid=pid, exists=None, inspection_error="linux-boot-id-malformed")
    return ProcessObservation(
        pid=pid,
        exists=True,
        process_birth_token=f"linux:{boot_id}:{fields[19]}",
    )


def observe_process(pid: int) -> ProcessObservation:
    """Inspect one live process without treating weak host evidence as success."""

    if not isinstance(pid, int) or isinstance(pid, bool) or pid < 1:
        raise WriterIdentityError("pid must be a positive integer")
    if os.name == "nt":
        return _windows_process_observation(pid)
    if sys.platform.startswith("linux"):
        return _linux_process_observation(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return ProcessObservation(pid=pid, exists=False)
    except PermissionError:
        return ProcessObservation(pid=pid, exists=None, inspection_error="process-inspection-denied")
    except OSError as exc:
        return ProcessObservation(
            pid=pid,
            exists=None,
            inspection_error=f"process-inspection-unavailable:{getattr(exc, 'errno', 'unknown')}",
        )
    return ProcessObservation(pid=pid, exists=True)


def create_current_writer_identity(
    *,
    writer_id: str,
    activation_digest: str,
    intent_digest: str,
    lease_duration_ns: int,
    now_ns: int | None = None,
    observer: ProcessObserver = observe_process,
) -> WriterIdentity:
    """Create an identity only when the current process birth is observable."""

    duration = _require_ns(lease_duration_ns, "lease_duration_ns")
    issued = time.time_ns() if now_ns is None else _require_ns(now_ns, "now_ns")
    observation = observer(os.getpid())
    if not isinstance(observation, ProcessObservation):
        raise WriterIdentityError("current process observer returned an invalid observation")
    if (
        observation.pid != os.getpid()
        or observation.exists is not True
        or observation.process_birth_token is None
    ):
        raise WriterIdentityError("current process birth identity is unavailable")
    return WriterIdentity(
        writer_id=writer_id,
        pid=os.getpid(),
        process_birth_token=observation.process_birth_token,
        activation_digest=activation_digest,
        intent_digest=intent_digest,
        lease_started_ns=issued,
        lease_expires_ns=issued + duration,
    )


def classify_writer_liveness(
    identity: WriterIdentity | None,
    *,
    now_ns: int | None = None,
    observer: ProcessObserver = observe_process,
) -> WriterLivenessReport:
    """Classify one persisted writer record without a stale-record shortcut."""

    if identity is None:
        return WriterLivenessReport(
            status=WriterLiveness.ABSENT,
            reason="no-writer-record",
            writer_identity_digest=None,
        )
    observed_at = time.time_ns() if now_ns is None else _require_ns(now_ns, "now_ns")
    identity_digest = identity.identity_digest
    if observed_at < identity.lease_started_ns:
        return WriterLivenessReport(
            status=WriterLiveness.INDETERMINATE,
            reason="observer-clock-precedes-lease",
            writer_identity_digest=identity_digest,
        )
    try:
        observation = observer(identity.pid)
    except Exception as exc:
        return WriterLivenessReport(
            status=WriterLiveness.INDETERMINATE,
            reason=f"process-observer-failed:{type(exc).__name__}",
            writer_identity_digest=identity_digest,
        )
    if not isinstance(observation, ProcessObservation) or observation.pid != identity.pid:
        return WriterLivenessReport(
            status=WriterLiveness.INDETERMINATE,
            reason="process-observer-returned-invalid-identity",
            writer_identity_digest=identity_digest,
        )
    if observation.exists is False:
        return WriterLivenessReport(
            status=WriterLiveness.INACTIVE,
            reason="process-not-found",
            writer_identity_digest=identity_digest,
        )
    if observation.exists is not True:
        return WriterLivenessReport(
            status=WriterLiveness.INDETERMINATE,
            reason=observation.inspection_error or "process-observation-unavailable",
            writer_identity_digest=identity_digest,
        )
    if observation.process_birth_token is None:
        return WriterLivenessReport(
            status=WriterLiveness.INDETERMINATE,
            reason="process-birth-token-unavailable",
            writer_identity_digest=identity_digest,
        )
    if observation.process_birth_token != identity.process_birth_token:
        return WriterLivenessReport(
            status=WriterLiveness.INACTIVE,
            reason="pid-reused-with-different-process-birth",
            writer_identity_digest=identity_digest,
            observed_process_birth_token=observation.process_birth_token,
        )
    if observed_at > identity.lease_expires_ns:
        return WriterLivenessReport(
            status=WriterLiveness.LEASE_EXPIRED,
            reason="matching-process-has-expired-lease",
            writer_identity_digest=identity_digest,
            observed_process_birth_token=observation.process_birth_token,
        )
    return WriterLivenessReport(
        status=WriterLiveness.LIVE,
        reason="matching-live-process-and-lease",
        writer_identity_digest=identity_digest,
        observed_process_birth_token=observation.process_birth_token,
    )


def require_recovery_permitted(report: WriterLivenessReport) -> None:
    """Reject cleanup whenever a writer may still own the control root."""

    if not isinstance(report, WriterLivenessReport):
        raise WriterIdentityError("writer liveness report is required")
    if not report.recovery_permitted:
        raise WriterIdentityError(
            "writer recovery is blocked by "
            f"{report.status.value.lower()} ({report.reason})"
        )
