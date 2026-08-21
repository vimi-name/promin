"""Strict, tools-only boundary for Promin client-report rendering.

Task 1 deliberately stops before PDF rendering.  The boundary is kept here so
the later renderer can be added without importing this tool from Core or the
public CLI.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import html
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from promin.canonical import CanonicalError, canonical_bytes, load_json_strict


class ClientReportToolError(ValueError):
    """Raised when a client report cannot safely enter the renderer."""


_REQUIRED_KEYS = frozenset({"claims", "inspection", "record_type", "schema"})
_INSPECTION_KEYS = frozenset(
    {
        "claims",
        "evidence_confidence",
        "record_type",
        "schema",
        "static_risk_counts",
        "status",
        "summary",
    }
)
_SUMMARY_KEYS = frozenset(
    {
        "declared_tool_profile_count",
        "directory_count",
        "documentation_status",
        "excluded_host_transient_bytes",
        "excluded_host_transient_file_count",
        "file_count",
        "recovery_status",
        "source_file_count",
    }
)
_INVENTORY_STATUSES = frozenset({"COMPLETE", "PARTIAL"})
_CAPABILITY_STATUSES = frozenset({"DECLARED", "PARTIAL", "UNAVAILABLE"})
_CONFIDENCE_LEVELS = frozenset({"BOUNDED_STATIC", "LIMITED"})


def _nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _validate_client_report(value: Any) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ClientReportToolError("client report must be a JSON object")
    claims = value.get("claims")
    if isinstance(claims, Mapping) and any(item is not False for item in claims.values()):
        raise ClientReportToolError("client report carries promoted claims")
    if set(value) != _REQUIRED_KEYS:
        raise ClientReportToolError("client report fields are not exact")
    if value.get("schema") != "promin.client-report.v1":
        raise ClientReportToolError("client report schema is invalid")
    if value.get("record_type") != "ProminClientReport":
        raise ClientReportToolError("client report record_type is invalid")
    if not isinstance(claims, Mapping):
        raise ClientReportToolError("client report claims must be an object")
    if any(item is not False for item in claims.values()):
        raise ClientReportToolError("client report carries promoted claims")
    inspection = value.get("inspection")
    if not isinstance(inspection, Mapping):
        raise ClientReportToolError("client report inspection must be an object")
    if set(inspection) != _INSPECTION_KEYS:
        raise ClientReportToolError("client report inspection fields are not exact")
    if inspection.get("schema") != "promin.product-inspection.v1":
        raise ClientReportToolError("client report inspection schema is invalid")
    if inspection.get("record_type") != "ProductInspectionClientSummary":
        raise ClientReportToolError("client report inspection record_type is invalid")
    summary = inspection.get("summary")
    if not isinstance(summary, Mapping) or set(summary) != _SUMMARY_KEYS:
        raise ClientReportToolError("client report inspection summary must be an object")
    for key in (
        "declared_tool_profile_count",
        "directory_count",
        "excluded_host_transient_bytes",
        "excluded_host_transient_file_count",
        "file_count",
        "source_file_count",
    ):
        if not _nonnegative_int(summary.get(key)):
            raise ClientReportToolError(f"client report summary field is invalid: {key}")
    if summary.get("documentation_status") not in _CAPABILITY_STATUSES:
        raise ClientReportToolError("client report summary documentation_status is invalid")
    if summary.get("recovery_status") not in _CAPABILITY_STATUSES:
        raise ClientReportToolError("client report summary recovery_status is invalid")
    if inspection.get("status") not in _INVENTORY_STATUSES:
        raise ClientReportToolError("client report inspection status is invalid")
    if not isinstance(inspection.get("static_risk_counts"), Mapping):
        raise ClientReportToolError("client report inspection risk counts must be an object")
    if any(
        not isinstance(key, str) or not _nonnegative_int(value)
        for key, value in inspection["static_risk_counts"].items()
    ):
        raise ClientReportToolError("client report inspection risk counts are invalid")
    confidence = inspection.get("evidence_confidence")
    if (
        not isinstance(confidence, Mapping)
        or set(confidence) != {"level", "limitations"}
        or confidence.get("level") not in _CONFIDENCE_LEVELS
        or not isinstance(confidence.get("limitations"), list)
        or any(not isinstance(item, str) for item in confidence["limitations"])
    ):
        raise ClientReportToolError("client report inspection confidence is invalid")
    if inspection.get("claims") != dict(claims):
        raise ClientReportToolError("client report inspection claims do not match")
    return value


def load_client_report(path: Path) -> dict[str, object]:
    """Load one exact canonical, claim-free client report."""

    source = Path(path)
    try:
        value = load_json_strict(source, root=source.parent)
        validated = _validate_client_report(value)
        raw = source.read_bytes()
        if canonical_bytes(value) != raw:
            raise ClientReportToolError("client report is not canonical")
    except ClientReportToolError:
        raise
    except (CanonicalError, OSError, TypeError, ValueError) as exc:
        raise ClientReportToolError(f"invalid canonical client report: {exc}") from exc
    return validated


def sha256_canonical(report: Mapping[str, object]) -> str:
    """Return the digest bound to the exact canonical report value."""

    return hashlib.sha256(canonical_bytes(dict(report))).hexdigest()


def _paragraph(text: str):
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph

    style = getSampleStyleSheet()["BodyText"]
    return Paragraph(html.escape(text).replace("\n", "<br/>"), style)


def _build_pdf(report: Mapping[str, object], destination: Path) -> None:
    """Build one client-facing PDF from the validated report only."""

    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    inspection = report["inspection"]
    assert isinstance(inspection, Mapping)
    summary = inspection["summary"]
    confidence = inspection["evidence_confidence"]
    assert isinstance(summary, Mapping)
    assert isinstance(confidence, Mapping)
    claims = report["claims"]
    assert isinstance(claims, Mapping)
    styles = getSampleStyleSheet()
    heading = styles["Heading2"]
    story = [Paragraph("Promin client report", styles["Title"]), Spacer(1, 0.15 * inch)]

    sections = (
        (
            "What Promin is",
            "Promin is described by this report as a tools-only, evidence-bounded workflow. "
            "This document reports the supplied fields and does not add runtime or release claims.",
        ),
        (
            "Minimal initialization",
            "Recovery status: " + str(summary["recovery_status"])
            + "; documentation status: " + str(summary["documentation_status"])
            + "; source files: " + str(summary["source_file_count"]),
        ),
        (
            "Expert configuration",
            "Declared tool profiles: " + str(summary["declared_tool_profile_count"])
            + "; files: " + str(summary["file_count"])
            + "; directories: " + str(summary["directory_count"]),
        ),
        (
            "Verified current evidence",
            "Inspection status: " + str(inspection["status"])
            + "; evidence confidence: " + str(confidence["level"])
            + "; static risk counts: " + json.dumps(inspection["static_risk_counts"], sort_keys=True),
        ),
        (
            "Evidence limits",
            "Claims are false: " + json.dumps(dict(claims), sort_keys=True)
            + ". Evidence limitations: " + "; ".join(str(item) for item in confidence["limitations"])
            + ". This report does not establish runtime, tool, platform, performance, visual, or acceptance success.",
        ),
        (
            "Next safe actions",
            "Review the source evidence, resolve stated limitations, and rerun the bounded checks before making any claim.",
        ),
    )
    for title, body in sections:
        story.extend((Paragraph(title, heading), _paragraph(body), Spacer(1, 0.12 * inch)))
    document = SimpleDocTemplate(str(destination), pagesize=LETTER, title="Promin client report")
    document.build(story)


def render_client_report(
    report: Mapping[str, object], output: Path
) -> dict[str, object]:
    """Render a validated report using create-only, same-directory publication."""

    validated = _validate_client_report(dict(report) if isinstance(report, Mapping) else report)
    destination = Path(output)
    if destination.exists():
        raise ClientReportToolError(f"output destination already exists: {destination}")
    if not destination.parent.is_dir():
        raise ClientReportToolError(f"output directory does not exist: {destination.parent}")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        os.close(fd)
        _build_pdf(validated, temporary)
        with temporary.open("r+b") as stream:
            stream.flush()
            os.fsync(stream.fileno())
            output_digest = hashlib.sha256(stream.read()).hexdigest()
        os.link(temporary, destination)
        temporary.unlink()
    except Exception as exc:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        if isinstance(exc, ClientReportToolError):
            raise
        raise ClientReportToolError(f"client PDF render failed: {exc}") from exc
    output_bytes = destination.stat().st_size
    return {
        "schema": "promin.client-report-render-receipt.v1",
        "record_type": "ClientReportRenderReceipt",
        "source_report_sha256": sha256_canonical(validated),
        "output_sha256": output_digest,
        "output_bytes": output_bytes,
        "claims": dict(validated["claims"]),
    }


__all__ = [
    "ClientReportToolError",
    "load_client_report",
    "render_client_report",
    "sha256_canonical",
]
