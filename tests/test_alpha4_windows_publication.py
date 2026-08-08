from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

import promin.publication as publication
from promin.publication import (
    PublicationError,
    SourcePublicationReceipt,
    publish_directory_create_only,
)
from promin.platform_paths import (
    PlatformPathError,
    WindowsCreateOnlyRenameReservation,
    physical_rename_directory_create_only,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _receipt(
    source: Path,
    membership_root: Path,
    *,
    authority: str = "source-authority",
    membership: str = "source-membership",
) -> SourcePublicationReceipt:
    return SourcePublicationReceipt(
        source=source,
        membership_root=membership_root,
        authority_digest=_digest(authority),
        membership_digest=_digest(membership),
    )


def _reservation(source: Path, destination: Path) -> WindowsCreateOnlyRenameReservation:
    return WindowsCreateOnlyRenameReservation(
        source=source,
        destination=destination,
        source_volume_serial=11,
        source_file_index=12,
        destination_parent=destination.parent,
        destination_parent_volume_serial=11,
        destination_parent_file_index=13,
    )


def test_source_preflight_failure_happens_before_platform_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "published"
    calls: list[str] = []

    def rejected_preflight(
        _source: Path, _membership_root: Path
    ) -> SourcePublicationReceipt:
        calls.append("preflight")
        raise PublicationError("portable source membership violation")

    def unexpected_platform(*_args: object, **_kwargs: object) -> Path:
        calls.append("platform")
        raise AssertionError("platform reservation must not run")

    monkeypatch.setattr(
        publication,
        "physical_rename_directory_create_only",
        unexpected_platform,
    )

    with pytest.raises(PublicationError, match="portable source membership violation"):
        publish_directory_create_only(
            source,
            destination,
            membership_root=tmp_path,
            source_preflight=rejected_preflight,
            authoritative_recheck=lambda expected, reservation: expected,
        )

    assert calls == ["preflight"]


def test_authoritative_drift_after_reservation_aborts_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "published"
    source.mkdir()
    expected = _receipt(source, tmp_path)
    calls: list[str] = []

    def source_preflight(
        observed_source: Path, membership_root: Path
    ) -> SourcePublicationReceipt:
        calls.append("preflight")
        assert observed_source == source
        assert membership_root == tmp_path
        return expected

    def platform(
        observed_source: Path,
        observed_destination: Path,
        *,
        after_reservation: object,
    ) -> Path:
        calls.append("reservation")
        assert callable(after_reservation)
        after_reservation(_reservation(observed_source, observed_destination))
        raise AssertionError("native rename must not run after authority drift")

    def recheck(
        observed_expected: SourcePublicationReceipt,
        reservation: WindowsCreateOnlyRenameReservation,
    ) -> SourcePublicationReceipt:
        calls.append("recheck")
        assert observed_expected == expected
        assert reservation.source == source
        return _receipt(source, tmp_path, authority="changed-after-reservation")

    monkeypatch.setattr(
        publication, "physical_rename_directory_create_only", platform
    )

    with pytest.raises(PublicationError, match="authority changed"):
        publish_directory_create_only(
            source,
            destination,
            membership_root=tmp_path,
            source_preflight=source_preflight,
            authoritative_recheck=recheck,
        )

    assert calls == ["preflight", "reservation", "recheck"]
    assert source.is_dir()
    assert not destination.exists()


def test_directory_overlap_is_rejected_without_platform_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = source / "nested-publication"
    calls: list[str] = []

    def unexpected_preflight(
        _source: Path, _membership_root: Path
    ) -> SourcePublicationReceipt:
        calls.append("preflight")
        raise AssertionError("overlap must be rejected before preflight")

    def unexpected_platform(*_args: object, **_kwargs: object) -> Path:
        calls.append("platform")
        raise AssertionError("overlap must be rejected before platform reservation")

    monkeypatch.setattr(
        publication,
        "physical_rename_directory_create_only",
        unexpected_platform,
    )

    with pytest.raises(PublicationError, match="overlap"):
        publish_directory_create_only(
            source,
            destination,
            membership_root=tmp_path,
            source_preflight=unexpected_preflight,
            authoritative_recheck=lambda expected, reservation: expected,
        )

    assert calls == []


def test_successful_filesystem_move_retains_all_acceptance_claims_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "published"
    source.mkdir()
    expected = _receipt(source, tmp_path)
    calls: list[str] = []

    def platform(
        observed_source: Path,
        observed_destination: Path,
        *,
        after_reservation: object,
    ) -> Path:
        calls.append("reservation")
        assert callable(after_reservation)
        after_reservation(_reservation(observed_source, observed_destination))
        calls.append("published")
        return observed_destination

    monkeypatch.setattr(
        publication, "physical_rename_directory_create_only", platform
    )

    result = publish_directory_create_only(
        source,
        destination,
        membership_root=tmp_path,
        source_preflight=lambda observed_source, membership_root: expected,
        authoritative_recheck=lambda observed_expected, reservation: expected,
    )

    assert calls == ["reservation", "published"]
    assert result.source == source
    assert result.destination == destination
    assert not result.authority
    assert not result.pass_credit
    assert not result.acceptance_pass
    assert not result.product_acceptance_pass
    assert not result.runtime_acceptance_pass
    assert not result.release_ready
    assert all(
        value is False
        for key, value in result.record().items()
        if key.endswith("pass") or key in {"authority", "pass_credit", "release_ready"}
    )


@pytest.mark.windows_integration
@pytest.mark.skipif(os.name != "nt", reason="native create-only publication is Windows-only")
def test_windows_drift_releases_native_reservation_without_destination(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "published"
    source.mkdir()
    payload = source / "payload.txt"
    payload.write_text("before", encoding="utf-8")
    expected = _receipt(source, tmp_path, authority=payload.read_text(encoding="utf-8"))

    def recheck(
        _expected: SourcePublicationReceipt,
        _reservation: WindowsCreateOnlyRenameReservation,
    ) -> SourcePublicationReceipt:
        payload.write_text("after", encoding="utf-8")
        return _receipt(source, tmp_path, authority=payload.read_text(encoding="utf-8"))

    with pytest.raises(PublicationError, match="authority changed"):
        publish_directory_create_only(
            source,
            destination,
            membership_root=tmp_path,
            source_preflight=lambda observed_source, membership_root: expected,
            authoritative_recheck=recheck,
        )

    assert source.is_dir()
    assert not destination.exists()
    released = tmp_path / "released-after-drift"
    source.rename(released)
    assert released.is_dir()


@pytest.mark.windows_integration
@pytest.mark.skipif(os.name != "nt", reason="native create-only publication is Windows-only")
def test_windows_native_primitive_rejects_overlapping_directory_before_callback(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    calls: list[str] = []

    with pytest.raises(PlatformPathError, match="overlap"):
        physical_rename_directory_create_only(
            source,
            source / "nested-publication",
            after_reservation=lambda reservation: calls.append("callback"),
        )

    assert calls == []
    assert source.is_dir()


@pytest.mark.windows_integration
@pytest.mark.skipif(os.name != "nt", reason="native create-only publication is Windows-only")
def test_windows_native_create_only_refuses_existing_destination(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "published"
    source.mkdir()
    destination.mkdir()
    expected = _receipt(source, tmp_path)

    with pytest.raises(FileExistsError, match="destination exists"):
        publish_directory_create_only(
            source,
            destination,
            membership_root=tmp_path,
            source_preflight=lambda observed_source, membership_root: expected,
            authoritative_recheck=lambda observed_expected, reservation: expected,
        )

    assert source.is_dir()
    assert destination.is_dir()


@pytest.mark.windows_integration
@pytest.mark.skipif(os.name != "nt", reason="native create-only publication is Windows-only")
def test_windows_native_create_only_directory_publication_succeeds_without_credit(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "published"
    source.mkdir()
    (source / "payload.txt").write_text("payload", encoding="utf-8")
    expected = _receipt(source, tmp_path, authority="payload-identity")

    result = publish_directory_create_only(
        source,
        destination,
        membership_root=tmp_path,
        source_preflight=lambda observed_source, membership_root: expected,
        authoritative_recheck=lambda observed_expected, reservation: expected,
    )

    assert not source.exists()
    assert destination.is_dir()
    assert (destination / "payload.txt").read_text(encoding="utf-8") == "payload"
    assert result.destination == destination
    assert not result.acceptance_pass
    assert not result.release_ready
