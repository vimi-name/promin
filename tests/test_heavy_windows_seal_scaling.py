from __future__ import annotations

import mmap
import os
from pathlib import Path

import pytest

from promin.windows_event_history import (
    WindowsEventHistorySeal,
    WindowsEventHistoryViolation,
)


pytestmark = pytest.mark.skipif(
    os.name != "nt", reason="Windows physical history seal operation proof"
)


def _history_files(root: Path, batch_count: int) -> tuple[Path, Path, list[Path], list[Path]]:
    journal = root / "journal"
    authority = root / "journal-authority" / "generation-scale"
    journal.mkdir(parents=True)
    authority.mkdir(parents=True)
    journal_files: list[Path] = []
    authority_files: list[Path] = []
    for sequence in range(1, batch_count + 1):
        journal_path = journal / f"{sequence:020d}-batch.json"
        authority_path = authority / f"{sequence:020d}-segment.json"
        journal_path.write_bytes(f"journal:{sequence}".encode("ascii"))
        authority_path.write_bytes(f"authority:{sequence}".encode("ascii"))
        journal_files.append(journal_path)
        authority_files.append(authority_path)
    return journal, authority, journal_files, authority_files


def _bind(seal: WindowsEventHistorySeal, *, sequence: int) -> None:
    seal.bind_verified_control(
        head={
            "sequence": sequence,
            "batch_id": f"batch:{sequence}",
            "batch_digest": f"digest:{sequence}",
        },
        authority_generation="generation-scale",
        head_payload=f"head:{sequence}".encode("ascii"),
        authority_root_payload=b"authority-root",
        checkpoint_payload=b"checkpoint",
    )


@pytest.mark.performance
def test_1604_batch_sequence_lookup_is_linear_and_reports_exact_handle_floor(
    tmp_path: Path,
) -> None:
    """The r5 contour uses 1,604 journal/authority file pairs.

    A legacy replay lookup inspected every held journal *and* authority member
    once per sequence: B * (2B) member visits.  The sealed index visits each
    journal path once at construction and one candidate per healthy lookup.
    The immutable handle count intentionally remains 2B: one live handle per
    file is the exact Windows share-mode floor for no-write/no-delete.
    """

    batch_count = 1_604
    root = tmp_path / "events"
    journal, authority, journal_files, authority_files = _history_files(
        root, batch_count
    )
    seal = WindowsEventHistorySeal.try_hold_existing(
        root=root,
        journal_directory=journal,
        authority_directory=authority,
        journal_files=journal_files,
        authority_files=authority_files,
        max_file_bytes=1_024,
    )
    assert seal is not None
    try:
        _bind(seal, sequence=batch_count)

        for sequence, expected in enumerate(journal_files, start=1):
            assert seal.journal_path_for_sequence(sequence) == expected.absolute()

        counters = seal.performance_counters
        immutable_count = 2 * batch_count
        assert counters.immutable_handles_live == immutable_count
        assert counters.long_lived_directory_handles_live == 3
        assert counters.admission_guard_handles_live == 0
        assert counters.native_handles_live == immutable_count + 3
        assert counters.immutable_handle_opens == immutable_count
        assert counters.immutable_witness_queries == 3 * immutable_count
        assert counters.directory_closure_checks == 2

        assert counters.journal_index_build_visits == batch_count
        assert counters.journal_path_lookups == batch_count
        assert counters.journal_path_candidates_examined == batch_count
        legacy_member_visits = batch_count * immutable_count
        indexed_member_visits = (
            counters.journal_index_build_visits
            + counters.journal_path_candidates_examined
        )
        assert legacy_member_visits == 5_145_632
        assert indexed_member_visits == 3_208
        assert legacy_member_visits // indexed_member_visits == batch_count

        # Boundary members retain the actual physical protection.  Neither a
        # same-size replacement nor deletion is permitted while the seal is
        # live, independent of the new lookup index.
        for protected in (
            journal_files[0],
            journal_files[-1],
            authority_files[0],
            authority_files[-1],
        ):
            original = protected.read_bytes()
            before = protected.stat()
            with pytest.raises(OSError):
                protected.write_bytes(b"x" * len(original))
            with pytest.raises(OSError):
                protected.unlink()
            after = protected.stat()
            assert protected.read_bytes() == original
            assert after.st_size == before.st_size
            assert after.st_mtime_ns == before.st_mtime_ns
    finally:
        seal.close()

    closed = seal.performance_counters
    assert closed.immutable_handles_live == 0
    assert closed.native_handles_live == 0


def test_sequence_index_preserves_ambiguous_prefix_rejection(tmp_path: Path) -> None:
    root = tmp_path / "events"
    journal = root / "journal"
    authority = root / "journal-authority" / "generation-scale"
    journal.mkdir(parents=True)
    authority.mkdir(parents=True)
    left = journal / "00000000000000000001-left.json"
    right = journal / "00000000000000000001-right.json"
    large_sequence = 10**20
    large = journal / f"{large_sequence:020d}-large.json"
    left.write_bytes(b"left")
    right.write_bytes(b"right")
    large.write_bytes(b"large")

    seal = WindowsEventHistorySeal.try_hold_existing(
        root=root,
        journal_directory=journal,
        authority_directory=authority,
        journal_files=[left, right, large],
        authority_files=[],
        max_file_bytes=1_024,
    )
    assert seal is not None
    try:
        with pytest.raises(
            WindowsEventHistoryViolation,
            match="sealed journal sequence is missing or ambiguous",
        ):
            seal.journal_path_for_sequence(1)
        assert seal.journal_path_for_sequence(large_sequence) == large.absolute()
        counters = seal.performance_counters
        assert counters.journal_index_build_visits == 3
        assert counters.journal_path_candidates_examined == 3
    finally:
        seal.close()


def test_preexisting_writable_mapping_prevents_physical_seal_admission(
    tmp_path: Path,
) -> None:
    """A writable section survives its source handle and remains a writer."""

    root = tmp_path / "events"
    journal = root / "journal"
    authority = root / "journal-authority" / "generation-scale"
    journal.mkdir(parents=True)
    authority.mkdir(parents=True)
    journal_path = journal / "00000000000000000001-mapped.json"
    journal_path.write_bytes(b"AAAA")

    source = journal_path.open("r+b", buffering=0)
    writable = mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_WRITE)
    source.close()
    try:
        before = writable[:]
        seal = WindowsEventHistorySeal.try_hold_existing(
            root=root,
            journal_directory=journal,
            authority_directory=authority,
            journal_files=[journal_path],
            authority_files=[],
            max_file_bytes=1_024,
        )
        assert seal is None
        writable[:1] = b"Z"
        writable.flush()
        assert writable[:] != before
    finally:
        writable.close()


def test_preexisting_writable_handle_prevents_physical_seal_admission(
    tmp_path: Path,
) -> None:
    root = tmp_path / "events"
    journal = root / "journal"
    authority = root / "journal-authority" / "generation-scale"
    journal.mkdir(parents=True)
    authority.mkdir(parents=True)
    journal_path = journal / "00000000000000000001-open-writer.json"
    journal_path.write_bytes(b"AAAA")

    writer = journal_path.open("r+b", buffering=0)
    try:
        seal = WindowsEventHistorySeal.try_hold_existing(
            root=root,
            journal_directory=journal,
            authority_directory=authority,
            journal_files=[journal_path],
            authority_files=[],
            max_file_bytes=1_024,
        )
        assert seal is None
        writer.write(b"Z")
        writer.flush()
    finally:
        writer.close()
