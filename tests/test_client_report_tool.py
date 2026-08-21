from __future__ import annotations

import json
import shutil
import struct
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from tools.promin_client_report import (
    ClientReportToolError,
    load_client_report,
    render_client_report,
    sha256_canonical,
)
from promin.canonical import canonical_bytes


@pytest.fixture
def valid_client_report() -> dict[str, object]:
    claims = {"acceptance_pass": False, "visual_acceptance": False}
    return {
        "claims": claims,
        "inspection": {
            "claims": claims,
            "evidence_confidence": {"level": "BOUNDED_STATIC", "limitations": []},
            "record_type": "ProductInspectionClientSummary",
            "schema": "promin.product-inspection.v1",
            "static_risk_counts": {},
            "status": "COMPLETE",
            "summary": {
                "declared_tool_profile_count": 0,
                "directory_count": 0,
                "documentation_status": "UNAVAILABLE",
                "excluded_host_transient_bytes": 0,
                "excluded_host_transient_file_count": 0,
                "file_count": 0,
                "recovery_status": "UNAVAILABLE",
                "source_file_count": 0,
            },
        },
        "record_type": "ProminClientReport",
        "schema": "promin.client-report.v1",
    }


def test_renderer_rejects_promoted_report(tmp_path: Path) -> None:
    source = tmp_path / "report.json"
    source.write_text('{"claims":{"acceptance_pass":true}}', encoding="utf-8")

    with pytest.raises(ClientReportToolError, match="promoted"):
        load_client_report(source)


def test_renderer_rejects_claim_free_noncanonical_report(
    valid_client_report: dict[str, object], tmp_path: Path
) -> None:
    source = tmp_path / "report.json"
    source.write_text(json.dumps(valid_client_report), encoding="utf-8")

    with pytest.raises(ClientReportToolError, match="not canonical"):
        load_client_report(source)


def test_renderer_refuses_existing_pdf_destination(
    valid_client_report: dict[str, object], tmp_path: Path
) -> None:
    destination = tmp_path / "client.pdf"
    destination.write_bytes(b"prior")

    with pytest.raises(ClientReportToolError, match="already exists"):
        render_client_report(valid_client_report, destination)


def test_pdf_receipt_binds_client_report_digest_and_false_claims(
    valid_client_report: dict[str, object], tmp_path: Path
) -> None:
    destination = tmp_path / "client.pdf"

    receipt = render_client_report(valid_client_report, destination)

    assert receipt["schema"] == "promin.client-report-render-receipt.v1"
    assert receipt["record_type"] == "ClientReportRenderReceipt"
    assert receipt["source_report_sha256"] == sha256_canonical(valid_client_report)
    assert receipt["claims"]["acceptance_pass"] is False  # type: ignore[index]
    published = destination.read_bytes()
    assert published.startswith(b"%PDF")
    import hashlib

    assert receipt["output_sha256"] == hashlib.sha256(published).hexdigest()
    assert receipt["output_bytes"] == len(published)


def test_render_failure_never_publishes_target(
    valid_client_report: dict[str, object], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import tools.promin_client_report as renderer_module

    monkeypatch.setattr(
        renderer_module,
        "_build_pdf",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("render fail")),
    )

    before = set(tmp_path.glob(".*.tmp"))
    with pytest.raises(ClientReportToolError, match="render fail"):
        render_client_report(valid_client_report, tmp_path / "client.pdf")
    assert not (tmp_path / "client.pdf").exists()
    assert set(tmp_path.glob(".*.tmp")) == before


def test_publication_failure_never_leaves_renderer_temp(
    valid_client_report: dict[str, object], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import tools.promin_client_report as renderer_module

    monkeypatch.setattr(renderer_module.os, "link", lambda *_args: (_ for _ in ()).throw(OSError("link fail")))
    before = set(tmp_path.glob(".*.tmp"))

    with pytest.raises(ClientReportToolError, match="link fail"):
        render_client_report(valid_client_report, tmp_path / "client.pdf")
    assert not (tmp_path / "client.pdf").exists()
    assert set(tmp_path.glob(".*.tmp")) == before


def test_fixture_pdf_contains_all_headings_and_poppler_page(
    valid_client_report: dict[str, object], tmp_path: Path
) -> None:
    destination = tmp_path / "fixture.pdf"
    render_client_report(valid_client_report, destination)
    headings = (
        "What Promin is",
        "Minimal initialization",
        "Expert configuration",
        "Verified current evidence",
        "Evidence limits",
        "Next safe actions",
    )
    import pdfplumber

    with pdfplumber.open(destination) as document:
        text = "\n".join(page.extract_text() or "" for page in document.pages)
    for heading in headings:
        assert heading in text
    assert "Claims are false" in text
    assert "does not establish runtime" in text

    pdftoppm = shutil.which("pdftoppm")
    if pdftoppm is None:
        pytest.skip("pdftoppm unavailable")
    prefix = tmp_path / "fixture-page"
    result = subprocess.run(
        [pdftoppm, "-f", "1", "-singlefile", "-png", str(destination), str(prefix)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    page = prefix.with_suffix(".png")
    data = page.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    width, height = struct.unpack(">II", data[16:24])
    assert width > 0 and height > 0


def test_loader_requires_exact_canonical_client_report(tmp_path: Path) -> None:
    source = tmp_path / "report.json"
    source.write_text(
        json.dumps(
            {
                "claims": {"acceptance_pass": False},
                "record_type": "ProminClientReport",
                "schema": "promin.client-report.v1",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ClientReportToolError, match="fields are not exact"):
        load_client_report(source)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("inspection.status", "UNKNOWN"),
        ("inspection.summary.file_count", -1),
        ("inspection.summary.documentation_status", "UNKNOWN"),
        ("inspection.static_risk_counts", {"risk": -1}),
        ("inspection.evidence_confidence", {"level": "BOUNDED_STATIC", "limitations": [1]}),
    ],
)
def test_loader_rejects_malformed_nested_client_surface(
    valid_client_report: dict[str, object], tmp_path: Path, path: str, value: object
) -> None:
    report = deepcopy(valid_client_report)
    cursor: object = report
    parts = path.split(".")
    for part in parts[:-1]:
        cursor = cursor[part]  # type: ignore[index]
    cursor[parts[-1]] = value  # type: ignore[index]
    source = tmp_path / "report.json"
    source.write_bytes(canonical_bytes(report))

    with pytest.raises(ClientReportToolError):
        load_client_report(source)
