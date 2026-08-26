from __future__ import annotations

from pathlib import Path

import pytest

from tests.test_verified_query_phase import (
    _check_begin_publication_race_with_service_close_is_serialized,
    _check_event_store_admission_is_atomic_with_phase_publication,
    _check_initialize_admission_is_atomic_with_phase_publication,
    _check_mutation_cleanup_preserves_original_exception_identity,
    _check_same_thread_commit_is_rejected_before_eventstore_reentry,
    _check_same_thread_recovery_is_rejected_before_eventstore_open,
    _check_verified_query_lease_entry_preserves_primary_exception_identity,
)


def test_begin_publication_race_with_service_close_is_serialized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _check_begin_publication_race_with_service_close_is_serialized(tmp_path, monkeypatch)


def test_event_store_admission_is_atomic_with_phase_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _check_event_store_admission_is_atomic_with_phase_publication(tmp_path, monkeypatch)


def test_initialize_admission_is_atomic_with_phase_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _check_initialize_admission_is_atomic_with_phase_publication(tmp_path, monkeypatch)


def test_verified_query_lease_entry_preserves_primary_exception_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _check_verified_query_lease_entry_preserves_primary_exception_identity(tmp_path, monkeypatch)


def test_same_thread_commit_is_rejected_before_eventstore_reentry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _check_same_thread_commit_is_rejected_before_eventstore_reentry(tmp_path, monkeypatch)


def test_same_thread_recovery_is_rejected_before_eventstore_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _check_same_thread_recovery_is_rejected_before_eventstore_open(tmp_path, monkeypatch)


def test_mutation_cleanup_preserves_original_exception_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _check_mutation_cleanup_preserves_original_exception_identity(tmp_path, monkeypatch)
