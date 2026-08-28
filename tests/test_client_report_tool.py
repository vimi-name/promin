from __future__ import annotations

import json
import itertools
import hashlib
import os
import shutil
import stat
import struct
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.promin_client_report import (
    ClientReportToolError,
    load_client_report,
    main,
    publish_evidence_packet,
    render_client_report,
    sha256_canonical,
)
from promin.canonical import canonical_bytes
from promin.product_inspection import inspect_product


# Independent fixture oracle: keep the expected 72-bucket scope literal so the
# test cannot reproduce production closure logic and accidentally agree with it.
_FIXTURE_BUCKET_KEYS = (
    ("promin", "init", "cold", 16),
    ("promin", "init", "cold", 64),
    ("promin", "init", "cold", 256),
    ("promin", "init", "warm", 16),
    ("promin", "init", "warm", 64),
    ("promin", "init", "warm", 256),
    ("promin", "update", "cold", 16),
    ("promin", "update", "cold", 64),
    ("promin", "update", "cold", 256),
    ("promin", "update", "warm", 16),
    ("promin", "update", "warm", 64),
    ("promin", "update", "warm", 256),
    ("promin", "query", "cold", 16),
    ("promin", "query", "cold", 64),
    ("promin", "query", "cold", 256),
    ("promin", "query", "warm", 16),
    ("promin", "query", "warm", 64),
    ("promin", "query", "warm", 256),
    ("promin", "docs", "cold", 16),
    ("promin", "docs", "cold", 64),
    ("promin", "docs", "cold", 256),
    ("promin", "docs", "warm", 16),
    ("promin", "docs", "warm", 64),
    ("promin", "docs", "warm", 256),
    ("markdown", "init", "cold", 16),
    ("markdown", "init", "cold", 64),
    ("markdown", "init", "cold", 256),
    ("markdown", "init", "warm", 16),
    ("markdown", "init", "warm", 64),
    ("markdown", "init", "warm", 256),
    ("markdown", "update", "cold", 16),
    ("markdown", "update", "cold", 64),
    ("markdown", "update", "cold", 256),
    ("markdown", "update", "warm", 16),
    ("markdown", "update", "warm", 64),
    ("markdown", "update", "warm", 256),
    ("markdown", "query", "cold", 16),
    ("markdown", "query", "cold", 64),
    ("markdown", "query", "cold", 256),
    ("markdown", "query", "warm", 16),
    ("markdown", "query", "warm", 64),
    ("markdown", "query", "warm", 256),
    ("markdown", "docs", "cold", 16),
    ("markdown", "docs", "cold", 64),
    ("markdown", "docs", "cold", 256),
    ("markdown", "docs", "warm", 16),
    ("markdown", "docs", "warm", 64),
    ("markdown", "docs", "warm", 256),
    ("empty", "init", "cold", 16),
    ("empty", "init", "cold", 64),
    ("empty", "init", "cold", 256),
    ("empty", "init", "warm", 16),
    ("empty", "init", "warm", 64),
    ("empty", "init", "warm", 256),
    ("empty", "update", "cold", 16),
    ("empty", "update", "cold", 64),
    ("empty", "update", "cold", 256),
    ("empty", "update", "warm", 16),
    ("empty", "update", "warm", 64),
    ("empty", "update", "warm", 256),
    ("empty", "query", "cold", 16),
    ("empty", "query", "cold", 64),
    ("empty", "query", "cold", 256),
    ("empty", "query", "warm", 16),
    ("empty", "query", "warm", 64),
    ("empty", "query", "warm", 256),
    ("empty", "docs", "cold", 16),
    ("empty", "docs", "cold", 64),
    ("empty", "docs", "cold", 256),
    ("empty", "docs", "warm", 16),
    ("empty", "docs", "warm", 64),
    ("empty", "docs", "warm", 256),
)

_FIXTURE_RESULT_KEY_CLOSURE = {
    "expected_bucket_count": 72,
    "observed_bucket_count": 72,
    "unique_bucket_count": 72,
    "complete": True,
    "missing": [],
    "missing_count": 0,
    "unexpected": [],
    "unexpected_count": 0,
    "duplicate": [],
    "duplicate_count": 0,
    "malformed_count": 0,
    "claim": False,
    "pass_credit": False,
}


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


def test_evidence_packet_requires_windows_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The evidence-bound packet API must exist and enforce its platform gate."""

    import tools.promin_client_report as renderer_module

    monkeypatch.setattr(renderer_module.platform, "system", lambda: "Linux")

    with pytest.raises(ClientReportToolError, match="Windows"):
        renderer_module.build_evidence_packet(
            tmp_path / "inspection.json",
            tmp_path / "saturation",
            tmp_path / "candidate.json",
            tmp_path / "comparative.json",
        )


def _packet_fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path, dict[str, object]]:
    project = tmp_path / "project"
    project.mkdir()
    (project / "README.md").write_text("fixture", encoding="utf-8")
    inspection_path = tmp_path / "inspection.json"
    inspection_path.write_bytes(canonical_bytes(inspect_product(project)))
    candidate_path = tmp_path / "candidate.json"
    candidate = {
        "record_type": "StandardReleaseCandidateBinding",
        "version": "1.0.0-alpha.4",
        "candidate_binding_digest": "fixture",
    }
    candidate_path.write_bytes(canonical_bytes(candidate))
    comparative = {
        "schema": "promin.comparative-benchmark.v1",
        "record_type": "ProminComparativeBenchmark",
        "claim": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "public_release_approved": False,
        "execution": {"performed": True, "status": "completed", "all_samples_succeeded": True, "full_comparison_scope_selected": True},
        "config": {"sizes": [16, 64, 256], "warmup_runs": 1, "measured_runs": 3, "sampling_interval_ms": 5, "scenarios": ["promin", "markdown", "empty"], "operations": ["init", "update", "query", "docs"], "temperatures": ["cold", "warm"], "execution_order": "sequential; no benchmark samples run concurrently", "fixed_workload": True, "fixed_bucket_count": 72},
        "results": [],
    }
    for scenario, operation, temperature, size in itertools.product(("promin", "markdown", "empty"), ("init", "update", "query", "docs"), ("cold", "warm"), (16, 64, 256)):
        comparative["results"].append({"scenario": scenario, "operation": operation, "temperature": temperature, "size": size, "status": "measured", "latency_ms": {"p50": 1.0, "p95": 2.0, "p99": 3.0}, "storage_total_bytes": {"p50": 4.0, "p95": 5.0, "p99": 6.0}, "claim": False, "pass_credit": False})
    assert len(_FIXTURE_BUCKET_KEYS) == 72
    assert {
        (row["scenario"], row["operation"], row["temperature"], row["size"])
        for row in comparative["results"]
    } == set(_FIXTURE_BUCKET_KEYS)
    comparative["result_key_closure"] = dict(_FIXTURE_RESULT_KEY_CLOSURE)
    comparative_path = tmp_path / "comparative.json"
    comparative_path.write_bytes(canonical_bytes(comparative))
    saturation_root = tmp_path / "saturation"
    saturation_root.mkdir()
    phases = ("physical-generation", "inventory", "semantic-ingestion", "projection", "runtime-queries", "result", "evidence-publication")
    events = []
    from promin.canonical import digest_value
    for phase, status in itertools.product(phases, ("started", "completed")):
        identity = {"schema": "promin.saturation-run-lifecycle.v1", "record_type": "SaturationRunLifecycleEvent", "run_id": "fixture-run", "sequence": len(events) + 1, "phase": phase, "status": status, "recorded_at": "2026-01-01T00:00:00Z", "pass_credit": False, "acceptance_pass": False, "product_acceptance_pass": False}
        events.append({**identity, "record_digest": digest_value(identity)})
    (saturation_root / "saturation-run-lifecycle.jsonl").write_bytes(b"".join(canonical_bytes(event) for event in events))
    result = {"artifact_binding": {"binding_digest": "sha256:" + "a" * 64, "platform": {"system": "windows", "binding_digest": "sha256:" + "b" * 64}}, "physical": {"files": 100000, "physical_relation_evidence_count": 198999, "semantic_control_records": 165, "semantic_control_envelopes": 137}, "search": {"actual_runtime_queries": 600}, "performance": {"observed": {"p50_ms": 1.0, "p95_ms": 2.0, "p99_ms": 3.0, "commit_p95_ms": 4.0, "commit_p99_ms": 5.0, "peak_rss_bytes": 6}, "predicates": {"within": True}}, "resources": {}, "contract_predicates": {"within": True}}
    result_path = saturation_root / "saturation-result.json"
    result_path.write_bytes(canonical_bytes(result))
    return inspection_path, saturation_root, candidate_path, comparative_path, result


def test_packet_rejects_nested_machine_claim_tamper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    inspection_path, _root, _candidate, _comparative, _result = _packet_fixture(tmp_path)
    tampered = json.loads(inspection_path.read_text(encoding="utf-8"))
    tampered["machine"]["claims"]["acceptance_pass"] = True
    inspection_path.write_bytes(canonical_bytes(tampered))
    with pytest.raises(ClientReportToolError, match="machine claims"):
        import tools.promin_client_report as module
        module._validate_inspection(tampered)


def test_packet_inspects_lifecycle_before_reading_lifecycle_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import tools.promin_client_report as module
    order: list[str] = []
    (tmp_path / "saturation").mkdir()
    monkeypatch.setattr(module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(module, "_load_canonical_source", lambda path, **_kwargs: ({}, b"{}"))
    monkeypatch.setattr(module, "_validate_inspection", lambda _value: {})
    monkeypatch.setattr(
        module,
        "validate_standard_release_candidate_binding",
        lambda value: {**value, "version": "1.0.0-alpha.4"},
    )
    monkeypatch.setattr(module, "_comparative_summary", lambda _value: [])
    monkeypatch.setattr(module, "inspect_saturation_lifecycle", lambda _root: (order.append("inspect") or {"status": "incomplete"}))
    monkeypatch.setattr(module, "_source_bytes", lambda path, **_kwargs: (order.append(f"read:{Path(path).name}") or b"{}"))
    with pytest.raises(ClientReportToolError, match="lifecycle"):
        module.build_evidence_packet(tmp_path / "inspection", tmp_path / "saturation", tmp_path / "candidate", tmp_path / "comparative")
    assert order == ["inspect"]


def test_packet_rejects_failed_comparative_bucket(tmp_path: Path) -> None:
    _inspection, _root, _candidate, comparative_path, _result = _packet_fixture(tmp_path)
    comparative = json.loads(comparative_path.read_text(encoding="utf-8"))
    comparative["results"][0]["status"] = "failed"
    comparative_path.write_bytes(canonical_bytes(comparative))
    with pytest.raises(ClientReportToolError, match="measured"):
        import tools.promin_client_report as module
        module._comparative_summary(comparative)


def test_packet_accepts_finite_signed_scaling_slope(tmp_path: Path) -> None:
    _inspection, _root, _candidate, comparative_path, _result = _packet_fixture(tmp_path)
    comparative = json.loads(comparative_path.read_text(encoding="utf-8"))
    comparative["scaling_checks"] = [
        {"p95_intervals": [{"p95_log_slope": -0.25}]}
    ]
    import tools.promin_client_report as module

    assert len(module._comparative_summary(comparative)) == 3


def test_packet_rejects_negative_unsigned_observation(tmp_path: Path) -> None:
    _inspection, _root, _candidate, comparative_path, _result = _packet_fixture(tmp_path)
    comparative = json.loads(comparative_path.read_text(encoding="utf-8"))
    comparative["results"][0]["latency_ms"]["p50"] = -1.0
    with pytest.raises(ClientReportToolError, match="observation"):
        import tools.promin_client_report as module
        module._comparative_summary(comparative)


def test_packet_accepts_r11_shaped_saturation_result_without_semantic_ingestion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import tools.promin_client_report as module
    inspection, root, candidate, comparative, result = _packet_fixture(tmp_path)
    monkeypatch.setattr(module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(module, "validate_standard_release_candidate_binding", lambda value: {**value, "candidate_binding_digest": "fixture-candidate"})
    monkeypatch.setattr(module, "validate_saturation_evidence", lambda *args, **kwargs: result)
    lifecycle = module.inspect_saturation_lifecycle(root)
    calls = {"count": 0}
    def inspect_again(_root: Path) -> dict[str, object]:
        calls["count"] += 1
        return lifecycle
    monkeypatch.setattr(module, "inspect_saturation_lifecycle", inspect_again)
    packet = module.build_evidence_packet(inspection, root, candidate, comparative)
    assert packet["platform"] == "windows"
    assert packet["claims"] == {key: False for key in module._EVIDENCE_CLAIMS}
    assert packet["saturation"]["physical_files"] == 100000
    assert calls["count"] == 2


def test_packet_rejects_structurally_valid_non_current_candidate_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tools.promin_client_report as module

    inspection, root, candidate, comparative, result = _packet_fixture(tmp_path)
    monkeypatch.setattr(module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        module,
        "validate_standard_release_candidate_binding",
        lambda value: {
            **value,
            "version": "1.0.1",
            "candidate_binding_digest": "fixture-candidate",
        },
    )
    monkeypatch.setattr(module, "validate_saturation_evidence", lambda *args, **kwargs: result)
    lifecycle = module.inspect_saturation_lifecycle(root)
    monkeypatch.setattr(module, "inspect_saturation_lifecycle", lambda _root: lifecycle)

    with pytest.raises(ClientReportToolError, match="version"):
        module.build_evidence_packet(inspection, root, candidate, comparative)


def test_packet_rejects_boolean_numeric_observation(tmp_path: Path) -> None:
    _inspection, _root, _candidate, comparative_path, _result = _packet_fixture(tmp_path)
    comparative = json.loads(comparative_path.read_text(encoding="utf-8"))
    comparative["results"][0]["latency_ms"]["p50"] = False
    with pytest.raises(ClientReportToolError, match="observation"):
        import tools.promin_client_report as module
        module._comparative_summary(comparative)


def test_packet_rejects_candidate_source_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import tools.promin_client_report as module
    inspection, root, candidate, comparative, result = _packet_fixture(tmp_path)
    monkeypatch.setattr(module.platform, "system", lambda: "Windows")
    def mutate(value: dict[str, object]) -> dict[str, object]:
        candidate.write_bytes(candidate.read_bytes() + b" ")
        return {**value, "candidate_binding_digest": "fixture-candidate"}
    monkeypatch.setattr(module, "validate_standard_release_candidate_binding", mutate)
    monkeypatch.setattr(module, "validate_saturation_evidence", lambda *args, **kwargs: result)
    lifecycle = module.inspect_saturation_lifecycle(root)
    monkeypatch.setattr(module, "inspect_saturation_lifecycle", lambda _root: lifecycle)
    with pytest.raises(ClientReportToolError, match="changed during validation"):
        module.build_evidence_packet(inspection, root, candidate, comparative)


def test_packet_rejects_non_windows_saturation_artifact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import tools.promin_client_report as module
    inspection, root, candidate, comparative, result = _packet_fixture(tmp_path)
    result["artifact_binding"]["platform"]["system"] = "linux"  # type: ignore[index]
    monkeypatch.setattr(module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(module, "validate_standard_release_candidate_binding", lambda value: {**value, "candidate_binding_digest": "fixture-candidate"})
    monkeypatch.setattr(module, "validate_saturation_evidence", lambda *args, **kwargs: result)
    lifecycle = module.inspect_saturation_lifecycle(root)
    monkeypatch.setattr(module, "inspect_saturation_lifecycle", lambda _root: lifecycle)
    with pytest.raises(ClientReportToolError, match="Windows"):
        module.build_evidence_packet(inspection, root, candidate, comparative)


def test_packet_rejects_forged_inspection_client_projection(tmp_path: Path) -> None:
    inspection_path, _root, _candidate, _comparative, _result = _packet_fixture(tmp_path)
    inspection = json.loads(inspection_path.read_text(encoding="utf-8"))
    inspection["client"]["summary"]["file_count"] = 999
    with pytest.raises(ClientReportToolError, match="client projection"):
        import tools.promin_client_report as module
        module._validate_inspection(inspection)


def test_packet_rejects_huge_numeric_observation_without_overflow(tmp_path: Path) -> None:
    _inspection, _root, _candidate, comparative_path, _result = _packet_fixture(tmp_path)
    comparative = json.loads(comparative_path.read_text(encoding="utf-8"))
    comparative["results"][0]["latency_ms"]["p50"] = 10**400
    with pytest.raises(ClientReportToolError, match="observation"):
        import tools.promin_client_report as module
        module._comparative_summary(comparative)


def test_packet_rejects_nested_boolean_sample_metric(tmp_path: Path) -> None:
    _inspection, _root, _candidate, comparative_path, _result = _packet_fixture(tmp_path)
    comparative = json.loads(comparative_path.read_text(encoding="utf-8"))
    comparative["results"][0]["samples"] = [{"measurement": {"wall_ms": False}}]
    with pytest.raises(ClientReportToolError, match="numeric"):
        import tools.promin_client_report as module
        module._comparative_summary(comparative)


def test_packet_rejects_absolute_path_in_allowed_inspection_shape(tmp_path: Path) -> None:
    inspection_path, _root, _candidate, _comparative, _result = _packet_fixture(tmp_path)
    inspection = json.loads(inspection_path.read_text(encoding="utf-8"))
    inspection["client"]["evidence_confidence"]["limitations"] = ["C:\\secret\\host.json"]
    inspection_path.write_bytes(canonical_bytes(inspection))
    with pytest.raises(ClientReportToolError):
        import tools.promin_client_report as module
        module._validate_inspection(inspection)


def test_source_loader_rejects_reparse_attribute_before_read_or_load(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tools.promin_client_report as module

    read_called = False
    load_called = False

    class ReparsePath:
        def lstat(self) -> SimpleNamespace:
            return SimpleNamespace(
                st_mode=stat.S_IFREG,
                st_size=2,
                st_file_attributes=0x00000400,
            )

        def read_bytes(self) -> bytes:
            nonlocal read_called
            read_called = True
            raise AssertionError("read_bytes must not run for a reparse point")

        def __str__(self) -> str:
            return "reparse-input.json"

    def load_json_that_must_not_run(*args: object, **kwargs: object) -> object:
        nonlocal load_called
        load_called = True
        raise AssertionError("load_json_strict must not run for a reparse point")

    monkeypatch.setattr(module, "load_json_strict", load_json_that_must_not_run)
    with pytest.raises(ClientReportToolError, match="regular file"):
        module._load_canonical_source(ReparsePath())  # type: ignore[arg-type]

    assert read_called is False
    assert load_called is False


def test_packet_rejects_saturation_root_symlink_before_child_reads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import tools.promin_client_report as module
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "saturation"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink creation unavailable")
    monkeypatch.setattr(module.platform, "system", lambda: "Windows")
    with pytest.raises(ClientReportToolError, match="real directory"):
        module.build_evidence_packet(tmp_path / "inspection", link, tmp_path / "candidate", tmp_path / "comparative")


def test_packet_rejects_saturation_root_identity_swap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import tools.promin_client_report as module
    inspection, root, candidate, comparative, result = _packet_fixture(tmp_path)
    monkeypatch.setattr(module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(module, "validate_standard_release_candidate_binding", lambda value: {**value, "candidate_binding_digest": "fixture-candidate"})
    monkeypatch.setattr(module, "validate_saturation_evidence", lambda *args, **kwargs: result)
    lifecycle = module.inspect_saturation_lifecycle(root)
    monkeypatch.setattr(module, "inspect_saturation_lifecycle", lambda _root: lifecycle)
    identities = iter(((1, 2, 3, 4), (1, 2, 3, 5)))
    monkeypatch.setattr(module, "_saturation_root_identity", lambda _root: next(identities))
    with pytest.raises(ClientReportToolError, match="root changed"):
        module.build_evidence_packet(inspection, root, candidate, comparative)


def test_packet_rejects_saturation_root_identity_change_during_final_rereads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A root swap after all child rereads must still fail closed."""

    import tools.promin_client_report as module

    inspection, root, candidate, comparative, result = _packet_fixture(tmp_path)
    monkeypatch.setattr(module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        module,
        "validate_standard_release_candidate_binding",
        lambda value: {**value, "candidate_binding_digest": "fixture-candidate"},
    )
    monkeypatch.setattr(module, "validate_saturation_evidence", lambda *args, **kwargs: result)
    lifecycle = module.inspect_saturation_lifecycle(root)
    monkeypatch.setattr(module, "inspect_saturation_lifecycle", lambda _root: lifecycle)

    original_assert_unchanged = module._assert_unchanged
    reread_names: list[str] = []
    root_changed = False

    def reread_then_swap(path: Path, original: bytes, **kwargs: object) -> None:
        nonlocal root_changed
        original_assert_unchanged(path, original, **kwargs)
        reread_names.append(Path(path).name)
        if len(reread_names) == 5:
            # The physical root identity changes after the final child bytes are
            # reread; every child remains byte-identical to its fixture snapshot.
            root_changed = True

    monkeypatch.setattr(module, "_assert_unchanged", reread_then_swap)
    identity_calls = 0

    def changing_identity(_root: Path) -> tuple[int, int, int, int]:
        nonlocal identity_calls
        identity_calls += 1
        return (1, 2, 3, 5 if root_changed else 4)

    monkeypatch.setattr(module, "_saturation_root_identity", changing_identity)
    fixture_bytes = {
        path: path.read_bytes()
        for path in (
            inspection,
            candidate,
            comparative,
            root / "saturation-result.json",
            root / "saturation-run-lifecycle.jsonl",
        )
    }

    with pytest.raises(ClientReportToolError, match="root changed"):
        module.build_evidence_packet(inspection, root, candidate, comparative)

    assert reread_names == [
        "inspection.json",
        "candidate.json",
        "comparative.json",
        "saturation-result.json",
        "saturation-run-lifecycle.jsonl",
    ]
    assert identity_calls == 3
    assert root_changed is True
    assert {path: path.read_bytes() for path in fixture_bytes} == fixture_bytes


@pytest.mark.parametrize("leaking_key", ["C:\\secret\\file", "\\\\server\\share", "/var/tmp/file", "2026-08-26T10:11:12Z", "123e4567-e89b-12d3-a456-426614174000", "hostname"])
def test_packet_rejects_leaking_mapping_keys(leaking_key: str) -> None:
    with pytest.raises(ClientReportToolError):
        import tools.promin_client_report as module
        module._assert_packet_safe({leaking_key: "safe"})


def test_packet_rejects_unknown_static_risk_code(tmp_path: Path) -> None:
    inspection_path, _root, _candidate, _comparative, _result = _packet_fixture(tmp_path)
    inspection = json.loads(inspection_path.read_text(encoding="utf-8"))
    inspection["machine"]["static_risk"]["by_code"]["invented-risk"] = 1
    with pytest.raises(ClientReportToolError, match="risk"):
        import tools.promin_client_report as module
        module._validate_inspection(inspection)


def test_packet_success_has_exact_canonical_closure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Assert the complete packet closure from hand-derived fixture literals.

    The two narrow validator patches isolate heavy external validation only;
    these fixed literals are still fed through the real packet assembly. Fresh
    physical Windows execution remains the final external gate, not unit proof.
    """

    import tools.promin_client_report as module

    inspection, root, candidate, comparative, result = _packet_fixture(tmp_path)
    monkeypatch.setattr(module.platform, "system", lambda: "Windows")

    expected_candidate = {
        "record_type": "StandardReleaseCandidateBinding",
        "version": "1.0.0-alpha.4",
        "candidate_binding_digest": "fixture",
    }
    expected_candidate_validated = {
        **expected_candidate,
        "candidate_binding_digest": "fixture-candidate",
    }
    expected_result = {
        "artifact_binding": {
            "binding_digest": "sha256:" + "a" * 64,
            "platform": {
                "system": "windows",
                "binding_digest": "sha256:" + "b" * 64,
            },
        },
        "physical": {
            "files": 100000,
            "physical_relation_evidence_count": 198999,
            "semantic_control_records": 165,
            "semantic_control_envelopes": 137,
        },
        "search": {"actual_runtime_queries": 600},
        "performance": {
            "observed": {
                "p50_ms": 1.0,
                "p95_ms": 2.0,
                "p99_ms": 3.0,
                "commit_p95_ms": 4.0,
                "commit_p99_ms": 5.0,
                "peak_rss_bytes": 6,
            },
            "predicates": {"within": True},
        },
        "resources": {},
        "contract_predicates": {"within": True},
    }
    assert candidate.read_bytes() == canonical_bytes(expected_candidate)
    assert result == expected_result

    candidate_calls: list[dict[str, object]] = []

    def validate_candidate_fixture(value: dict[str, object]) -> dict[str, object]:
        assert value == expected_candidate
        candidate_calls.append(value)
        return expected_candidate_validated

    saturation_calls: list[dict[str, object]] = []

    def validate_saturation_fixture(value: dict[str, object], **kwargs: object) -> dict[str, object]:
        assert value == expected_result
        assert kwargs == {
            "candidate_binding": expected_candidate_validated,
            "source_path": root / "saturation-result.json",
            "evidence_root": root,
            "require_pass": True,
        }
        saturation_calls.append(value)
        return value

    monkeypatch.setattr(module, "validate_standard_release_candidate_binding", validate_candidate_fixture)
    monkeypatch.setattr(module, "validate_saturation_evidence", validate_saturation_fixture)
    lifecycle = module.inspect_saturation_lifecycle(root)
    monkeypatch.setattr(module, "inspect_saturation_lifecycle", lambda _root: lifecycle)

    packet = module.build_evidence_packet(inspection, root, candidate, comparative)
    assert candidate_calls == [expected_candidate]
    assert saturation_calls == [expected_result]

    expected_claims = {
        "acceptance_pass": False,
        "pass_credit": False,
        "product_acceptance_pass": False,
        "runtime_validated": False,
        "performance_acceptance": False,
        "visual_acceptance": False,
        "release_eligible": False,
        "comparative_superiority": False,
        "proxy_acceptance": False,
    }
    expected_report = {
        "schema": "promin.client-report.v1",
        "record_type": "ProminClientReport",
        "claims": {
            "acceptance_pass": False,
            "pass_credit": False,
            "product_acceptance_pass": False,
            "release_eligible": False,
            "runtime_validated": False,
        },
        "inspection": {
            "schema": "promin.product-inspection.v1",
            "record_type": "ProductInspectionClientSummary",
            "status": "COMPLETE",
            "summary": {
                "declared_tool_profile_count": 0,
                "directory_count": 0,
                "documentation_status": "DECLARED",
                "excluded_host_transient_bytes": 0,
                "excluded_host_transient_file_count": 0,
                "file_count": 1,
                "recovery_status": "UNAVAILABLE",
                "source_file_count": 0,
            },
            "static_risk_counts": {},
            "evidence_confidence": {
                "level": "BOUNDED_STATIC",
                "limitations": [
                    "no-provider-execution",
                    "no-configure-execution",
                    "no-build-execution",
                    "no-runtime-execution",
                    "no-database-access",
                    "lexical-dependency-signals-are-review-only",
                ],
            },
            "claims": {
                "acceptance_pass": False,
                "pass_credit": False,
                "product_acceptance_pass": False,
                "release_eligible": False,
                "runtime_validated": False,
            },
        },
    }
    expected_bindings = {
        "inspection": {
            "sha256": "2b36114a13c2b6ca87f4cc872324db070fd576bb08850bec8b289c1d5547dac8",
            "bytes": 4090,
        },
            "candidate_binding": {
                "sha256": "6e802f2d1c153bbcb7c0b534f1f4ee32b3de18858be2e0b943c15f6ac0e1fdb0",
                "bytes": 113,
        },
            "saturation_result": {
                "sha256": "5bbc129c468ea292e6a5824ec2e170fe3ccfbc7870f86467346cc1afd79e47b9",
                "bytes": 620,
        },
        "saturation_lifecycle": {
            "sha256": "13e1294bef15c14f31562fdedc371fc7983edf9db03883d8e50de31a9738d34d",
            "bytes": 5169,
        },
        "comparative": {
            "sha256": "8bc807abe828e90f0333ff514e4031cd8763a96b0145d0a01cd8b1d09c2b2292",
            "bytes": 17243,
        },
        "candidate_binding_digest": "fixture-candidate",
        "artifact_binding_digest": "sha256:" + "a" * 64,
        "platform_binding_digest": "sha256:" + "b" * 64,
    }
    assert set(packet) == {
        "schema",
        "record_type",
        "platform",
        "claims",
        "inspection",
        "saturation",
        "comparative",
        "input_bindings",
    }
    assert packet["schema"] == "promin.client-report-evidence.v1"
    assert packet["record_type"] == "ProminClientReportEvidence"
    assert packet["platform"] == "windows"
    assert packet["claims"] == expected_claims
    assert set(packet["inspection"]) == {"source_sha256", "source_bytes", "report"}
    assert packet["inspection"] == {
        "source_sha256": expected_bindings["inspection"]["sha256"],
        "source_bytes": expected_bindings["inspection"]["bytes"],
        "report": expected_report,
    }
    assert set(packet["inspection"]["report"]) == {"schema", "record_type", "claims", "inspection"}
    assert set(packet["inspection"]["report"]["claims"]) == {
        "acceptance_pass", "pass_credit", "product_acceptance_pass", "release_eligible", "runtime_validated"
    }
    assert set(packet["inspection"]["report"]["inspection"]) == {
        "schema", "record_type", "status", "summary", "static_risk_counts", "evidence_confidence", "claims"
    }
    assert set(packet["inspection"]["report"]["inspection"]["summary"]) == {
        "declared_tool_profile_count", "directory_count", "documentation_status",
        "excluded_host_transient_bytes", "excluded_host_transient_file_count", "file_count",
        "recovery_status", "source_file_count",
    }
    assert set(packet["inspection"]["report"]["inspection"]["evidence_confidence"]) == {"level", "limitations"}
    assert set(packet["saturation"]) == {
        "result_sha256", "result_bytes", "lifecycle_sha256", "lifecycle_bytes", "physical_files",
        "physical_relations", "runtime_queries", "semantic_control_records", "semantic_control_envelopes",
        "query_p50_ms", "query_p95_ms", "query_p99_ms", "commit_p95_ms", "commit_p99_ms",
        "peak_rss_bytes", "all_predicates",
    }
    assert packet["saturation"] == {
        "result_sha256": expected_bindings["saturation_result"]["sha256"],
        "result_bytes": expected_bindings["saturation_result"]["bytes"],
        "lifecycle_sha256": expected_bindings["saturation_lifecycle"]["sha256"],
        "lifecycle_bytes": expected_bindings["saturation_lifecycle"]["bytes"],
        "physical_files": 100000,
        "physical_relations": 198999,
        "runtime_queries": 600,
        "semantic_control_records": 165,
        "semantic_control_envelopes": 137,
        "query_p50_ms": 1.0,
        "query_p95_ms": 2.0,
        "query_p99_ms": 3.0,
        "commit_p95_ms": 4.0,
        "commit_p99_ms": 5.0,
        "peak_rss_bytes": 6,
        "all_predicates": {"within": True},
    }
    assert set(packet["saturation"]["all_predicates"]) == {"within"}
    assert packet["comparative"] == {
        "source_sha256": expected_bindings["comparative"]["sha256"],
        "source_bytes": expected_bindings["comparative"]["bytes"],
        "scenarios": [
            {"scenario": "promin", "bucket_count": 24, "median_latency_p50_ms": 1.0, "median_storage_p50_bytes": 4.0},
            {"scenario": "markdown", "bucket_count": 24, "median_latency_p50_ms": 1.0, "median_storage_p50_bytes": 4.0},
            {"scenario": "empty", "bucket_count": 24, "median_latency_p50_ms": 1.0, "median_storage_p50_bytes": 4.0},
        ],
    }
    assert set(packet["comparative"]) == {"source_sha256", "source_bytes", "scenarios"}
    assert all(set(row) == {"scenario", "bucket_count", "median_latency_p50_ms", "median_storage_p50_bytes"} for row in packet["comparative"]["scenarios"])
    assert packet["input_bindings"] == expected_bindings
    assert set(packet["input_bindings"]) == {
        "inspection", "candidate_binding", "saturation_result", "saturation_lifecycle", "comparative",
        "candidate_binding_digest", "artifact_binding_digest", "platform_binding_digest",
    }
    assert all(set(packet["input_bindings"][name]) == {"sha256", "bytes"} for name in (
        "inspection", "candidate_binding", "saturation_result", "saturation_lifecycle", "comparative"
    ))

    packet_bytes = canonical_bytes(packet)
    assert json.loads(packet_bytes) == packet
    assert canonical_bytes(json.loads(packet_bytes)) == packet_bytes
    module._assert_packet_safe(packet)


def _publication_packet() -> dict[str, object]:
    claims = {
        "acceptance_pass": False,
        "pass_credit": False,
        "product_acceptance_pass": False,
        "runtime_validated": False,
        "performance_acceptance": False,
        "visual_acceptance": False,
        "release_eligible": False,
        "comparative_superiority": False,
        "proxy_acceptance": False,
    }
    report_claims = {
        "acceptance_pass": False,
        "pass_credit": False,
        "product_acceptance_pass": False,
        "release_eligible": False,
        "runtime_validated": False,
    }
    report = {
        "schema": "promin.client-report.v1",
        "record_type": "ProminClientReport",
        "claims": report_claims,
        "inspection": {
            "schema": "promin.product-inspection.v1",
            "record_type": "ProductInspectionClientSummary",
            "status": "COMPLETE",
            "summary": {
                "declared_tool_profile_count": 2,
                "directory_count": 3,
                "documentation_status": "DECLARED",
                "excluded_host_transient_bytes": 0,
                "excluded_host_transient_file_count": 0,
                "file_count": 8,
                "recovery_status": "PARTIAL",
                "source_file_count": 6,
            },
            "static_risk_counts": {},
            "evidence_confidence": {
                "level": "BOUNDED_STATIC",
                "limitations": ["no-runtime-execution"],
            },
            "claims": report_claims,
        },
    }
    source = {
        "inspection": {"sha256": "1" * 64, "bytes": 100},
        "candidate_binding": {"sha256": "2" * 64, "bytes": 200},
        "saturation_result": {"sha256": "3" * 64, "bytes": 300},
        "saturation_lifecycle": {"sha256": "4" * 64, "bytes": 400},
        "comparative": {"sha256": "5" * 64, "bytes": 500},
    }
    return {
        "schema": "promin.client-report-evidence.v1",
        "record_type": "ProminClientReportEvidence",
        "platform": "windows",
        "claims": claims,
        "inspection": {
            "source_sha256": source["inspection"]["sha256"],
            "source_bytes": source["inspection"]["bytes"],
            "report": report,
        },
        "saturation": {
            "result_sha256": source["saturation_result"]["sha256"],
            "result_bytes": source["saturation_result"]["bytes"],
            "lifecycle_sha256": source["saturation_lifecycle"]["sha256"],
            "lifecycle_bytes": source["saturation_lifecycle"]["bytes"],
            "physical_files": 100000,
            "physical_relations": 198999,
            "runtime_queries": 600,
            "semantic_control_records": 165,
            "semantic_control_envelopes": 137,
            "query_p50_ms": 1.0,
            "query_p95_ms": 2.0,
            "query_p99_ms": 3.0,
            "commit_p95_ms": 4.0,
            "commit_p99_ms": 5.0,
            "peak_rss_bytes": 6,
            "all_predicates": {"within": True, "complete": False},
        },
        "comparative": {
            "source_sha256": source["comparative"]["sha256"],
            "source_bytes": source["comparative"]["bytes"],
            "scenarios": [
                {"scenario": "promin", "bucket_count": 24, "median_latency_p50_ms": 1.0, "median_storage_p50_bytes": 4.0},
                {"scenario": "markdown", "bucket_count": 24, "median_latency_p50_ms": 2.0, "median_storage_p50_bytes": 5.0},
                {"scenario": "empty", "bucket_count": 24, "median_latency_p50_ms": 3.0, "median_storage_p50_bytes": 6.0},
            ],
        },
        "input_bindings": {
            **source,
            "candidate_binding_digest": "a" * 64,
            "artifact_binding_digest": "sha256:" + "b" * 64,
            "platform_binding_digest": "sha256:" + "c" * 64,
        },
    }


def _publication_baseline_bytes(
    packet: dict[str, object], tmp_path: Path,
) -> dict[str, bytes]:
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    publish_evidence_packet(
        packet,
        baseline / "report.json",
        baseline / "report.pdf",
        baseline / "receipt.json",
    )
    return {
        "report": (baseline / "report.json").read_bytes(),
        "pdf": (baseline / "report.pdf").read_bytes(),
        "receipt": (baseline / "receipt.json").read_bytes(),
    }


@pytest.mark.parametrize(
    ("records", "envelopes"),
    [(100000, 137), (165, 100000), (164, 137)],
)
def test_packet_rejects_noncanonical_semantic_control_counts(
    records: int, envelopes: int,
) -> None:
    import tools.promin_client_report as module

    packet = _publication_packet()
    saturation = packet["saturation"]
    assert isinstance(saturation, dict)
    saturation["semantic_control_records"] = records
    saturation["semantic_control_envelopes"] = envelopes

    with pytest.raises(ClientReportToolError, match="semantic control"):
        module._validate_evidence_packet(packet)


def test_publish_packet_rejects_non_windows_before_output_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tools.promin_client_report as module

    monkeypatch.setattr(module.platform, "system", lambda: "Linux")
    io_calls: list[Path] = []

    def record_destination(path: Path) -> None:
        io_calls.append(path)

    def fail_temp(path: Path) -> Path:
        io_calls.append(path)
        raise AssertionError("publication temporary I/O must not run")

    monkeypatch.setattr(module, "_validate_publication_destination", record_destination)
    monkeypatch.setattr(module, "_make_publication_temp", fail_temp)

    with pytest.raises(ClientReportToolError, match="Windows"):
        publish_evidence_packet(
            _publication_packet(),
            tmp_path / "report.json",
            tmp_path / "report.pdf",
            tmp_path / "receipt.json",
        )

    assert io_calls == []


def test_publish_packet_writes_canonical_report_pdf_and_receipt(tmp_path: Path) -> None:
    packet = _publication_packet()
    report_out = tmp_path / "report.json"
    pdf_out = tmp_path / "report.pdf"
    receipt_out = tmp_path / "receipt.json"

    receipt = publish_evidence_packet(packet, report_out, pdf_out, receipt_out)

    assert report_out.read_bytes() == canonical_bytes(packet)
    assert pdf_out.read_bytes().startswith(b"%PDF")
    assert set(receipt) == {
        "schema", "record_type", "platform", "input_digests",
        "candidate_binding_digest", "saturation_result_digest",
        "saturation_lifecycle_sha256", "comparative_sha256",
        "bound_report_sha256", "pdf_sha256", "pdf_bytes", "claims",
        "receipt_digest",
    }
    unsigned = dict(receipt)
    unsigned.pop("receipt_digest")
    assert receipt["receipt_digest"] == hashlib.sha256(canonical_bytes(unsigned)).hexdigest()
    assert json.loads(receipt_out.read_bytes()) == receipt


def test_publish_packet_is_byte_deterministic_at_distinct_destinations(tmp_path: Path) -> None:
    packet = _publication_packet()
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    first_receipt = publish_evidence_packet(packet, first / "report.json", first / "report.pdf", first / "receipt.json")
    second_receipt = publish_evidence_packet(packet, second / "report.json", second / "report.pdf", second / "receipt.json")

    assert (first / "report.json").read_bytes() == (second / "report.json").read_bytes()
    assert (first / "report.pdf").read_bytes() == (second / "report.pdf").read_bytes()
    assert (first / "receipt.json").read_bytes() == (second / "receipt.json").read_bytes()
    assert first_receipt == second_receipt


def test_publish_packet_pdf_contains_six_sections_counts_and_no_forbidden_words(tmp_path: Path) -> None:
    packet = _publication_packet()
    destination = (tmp_path / "report.json", tmp_path / "report.pdf", tmp_path / "receipt.json")
    publish_evidence_packet(packet, *destination)

    from pypdf import PdfReader

    text = "\n".join(page.extract_text() or "" for page in PdfReader(str(destination[1])).pages)
    for heading in (
        "Evidence scope",
        "What Promin is and can do",
        "Host-local comparison (Promin / Markdown / Empty baseline)",
        "Exact Windows scale (100000 / 198999 / 600)",
        "Product inspection",
        "Limitations and next safe actions",
    ):
        assert heading in text
    for label in ("Promin", "Markdown", "Empty"):
        assert label in text
    assert "100000" in text and "198999" in text and "600" in text
    assert "not feature-equivalent" in text
    assert "observed host-local measurement" in text
    assert "capability distinction" in text
    lowered = text.casefold()
    for forbidden in ("faster", "better", "production-ready", "accepted", "release-ready"):
        assert forbidden not in lowered


def test_publish_packet_rejects_collision_before_creating_temps(tmp_path: Path) -> None:
    packet = _publication_packet()
    destination = tmp_path / "same.json"
    with pytest.raises(ClientReportToolError, match="distinct"):
        publish_evidence_packet(packet, destination, destination, tmp_path / "receipt.json")
    assert list(tmp_path.iterdir()) == []


def test_publish_packet_failure_leaves_sentinel_and_no_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import tools.promin_client_report as module

    sentinel = tmp_path / "sentinel.json"
    sentinel.write_bytes(b"sentinel")
    monkeypatch.setattr(module, "_build_evidence_pdf", lambda *_args: (_ for _ in ()).throw(RuntimeError("render fail")))
    with pytest.raises(ClientReportToolError, match="render fail"):
        publish_evidence_packet(_publication_packet(), tmp_path / "report.json", tmp_path / "report.pdf", tmp_path / "receipt.json")
    assert sentinel.read_bytes() == b"sentinel"
    assert not (tmp_path / "report.json").exists()
    assert not (tmp_path / "report.pdf").exists()


def test_client_report_cli_success_publishes_outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import tools.promin_client_report as module

    monkeypatch.setattr(module, "build_evidence_packet", lambda *_args: _publication_packet())
    paths = [tmp_path / name for name in ("inspection.json", "saturation", "candidate.json", "comparative.json")]
    paths[1].mkdir()
    args = [
        "--inspection", str(paths[0]),
        "--saturation-root", str(paths[1]),
        "--candidate-binding", str(paths[2]),
        "--comparative", str(paths[3]),
        "--report-out", str(tmp_path / "report.json"),
        "--pdf-out", str(tmp_path / "report.pdf"),
        "--receipt-out", str(tmp_path / "receipt.json"),
    ]
    assert main(args) == 0
    assert (tmp_path / "report.json").is_file()
    assert (tmp_path / "report.pdf").is_file()
    assert (tmp_path / "receipt.json").is_file()


@pytest.mark.parametrize("failing_role", ["report", "pdf", "receipt"])
def test_publication_identity_failure_is_bookkept_and_cleaned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failing_role: str
) -> None:
    import tools.promin_client_report as module

    packet = _publication_packet()
    expected = _publication_baseline_bytes(packet, tmp_path)
    destinations = {
        "report": tmp_path / "report.json",
        "pdf": tmp_path / "report.pdf",
        "receipt": tmp_path / "receipt.json",
    }
    original_identity = module._published_identity

    def fail_for_one(path: Path) -> tuple[int, int]:
        if path == destinations[failing_role]:
            raise ClientReportToolError("identity inspection failure")
        return original_identity(path)

    monkeypatch.setattr(module, "_published_identity", fail_for_one)
    with pytest.raises(ClientReportToolError, match="identity inspection failure"):
        publish_evidence_packet(packet, **{f"{key}_out": value for key, value in destinations.items()})
    order = ("report", "pdf", "receipt")
    failing_index = order.index(failing_role)
    for index, name in enumerate(order):
        if index <= failing_index:
            assert destinations[name].read_bytes() == expected[name]
        else:
            assert not destinations[name].exists()
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("replaced_role", ["report", "pdf", "receipt"])
def test_publication_race_refuses_to_remove_replaced_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replaced_role: str
) -> None:
    import tools.promin_client_report as module

    packet = _publication_packet()
    expected = _publication_baseline_bytes(packet, tmp_path)
    destinations = {
        "report": tmp_path / "report.json",
        "pdf": tmp_path / "report.pdf",
        "receipt": tmp_path / "receipt.json",
    }
    original_link = module.os.link
    sentinel = b"concurrent replacement sentinel"

    def link_then_replace(source: Path, destination: Path) -> None:
        original_link(source, destination)
        if destination == destinations[replaced_role]:
            destination.unlink()
            destination.write_bytes(sentinel)

    monkeypatch.setattr(module.os, "link", link_then_replace)
    with pytest.raises(ClientReportToolError, match="identity"):
        publish_evidence_packet(packet, **{f"{key}_out": value for key, value in destinations.items()})
    assert destinations[replaced_role].read_bytes() == sentinel
    order = ("report", "pdf", "receipt")
    replaced_index = order.index(replaced_role)
    for index, name in enumerate(order):
        if index < replaced_index:
            assert destinations[name].read_bytes() == expected[name]
        elif name != replaced_role:
            assert not destinations[name].exists()
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("failing_role", ["report", "pdf", "receipt"])
def test_publication_link_failure_cleans_only_owned_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failing_role: str
) -> None:
    import tools.promin_client_report as module

    packet = _publication_packet()
    expected = _publication_baseline_bytes(packet, tmp_path)
    destinations = {
        "report": tmp_path / "report.json",
        "pdf": tmp_path / "report.pdf",
        "receipt": tmp_path / "receipt.json",
    }
    unrelated = tmp_path / "unrelated.sentinel"
    unrelated.write_bytes(b"unrelated sentinel")
    original_link = module.os.link

    def fail_one(source: Path, destination: Path) -> None:
        if destination == destinations[failing_role]:
            raise OSError("link failure")
        original_link(source, destination)

    monkeypatch.setattr(module.os, "link", fail_one)
    with pytest.raises(ClientReportToolError, match="link failure"):
        publish_evidence_packet(packet, **{f"{key}_out": value for key, value in destinations.items()})
    assert unrelated.read_bytes() == b"unrelated sentinel"
    order = ("report", "pdf", "receipt")
    failing_index = order.index(failing_role)
    for index, name in enumerate(order):
        if index < failing_index:
            assert destinations[name].read_bytes() == expected[name]
        else:
            assert not destinations[name].exists()
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("reparse_role", ["report", "pdf", "receipt"])
def test_publication_cleanup_refuses_simulated_reparse_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reparse_role: str
) -> None:
    import tools.promin_client_report as module

    packet = _publication_packet()
    expected = _publication_baseline_bytes(packet, tmp_path)
    destinations = {
        "report": tmp_path / "report.json",
        "pdf": tmp_path / "report.pdf",
        "receipt": tmp_path / "receipt.json",
    }
    sentinel = b"simulated reparse replacement"
    original_link = module.os.link
    original_lstat = Path.lstat
    metadata_reparse = False

    def link_then_replace(source: Path, destination: Path) -> None:
        nonlocal metadata_reparse
        original_link(source, destination)
        if destination == destinations[reparse_role]:
            destination.unlink()
            destination.write_bytes(sentinel)
            metadata_reparse = True

    def reparse_lstat(path: Path) -> object:
        info = original_lstat(path)
        if metadata_reparse and path == destinations[reparse_role]:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_dev=info.st_dev,
                st_ino=info.st_ino,
                st_file_attributes=0x00000400,
            )
        return info

    monkeypatch.setattr(module.os, "link", link_then_replace)
    monkeypatch.setattr(Path, "lstat", reparse_lstat)
    with pytest.raises(ClientReportToolError, match="regular file|identity"):
        publish_evidence_packet(packet, **{f"{key}_out": value for key, value in destinations.items()})
    assert destinations[reparse_role].read_bytes() == sentinel
    order = ("report", "pdf", "receipt")
    replaced_index = order.index(reparse_role)
    for index, name in enumerate(order):
        if index < replaced_index:
            assert destinations[name].read_bytes() == expected[name]
        elif name != reparse_role:
            assert not destinations[name].exists()
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("existing_role", ["report", "pdf", "receipt"])
def test_publication_preexisting_destination_is_untouched(
    tmp_path: Path, existing_role: str
) -> None:
    destinations = {
        "report": tmp_path / "report.json",
        "pdf": tmp_path / "report.pdf",
        "receipt": tmp_path / "receipt.json",
    }
    sentinel = b"pre-existing sentinel"
    destinations[existing_role].write_bytes(sentinel)

    with pytest.raises(ClientReportToolError, match="already exists"):
        publish_evidence_packet(_publication_packet(), **{f"{key}_out": value for key, value in destinations.items()})
    assert destinations[existing_role].read_bytes() == sentinel
    assert all(not path.exists() for key, path in destinations.items() if key != existing_role)
    assert not list(tmp_path.glob(".*.tmp"))


def test_publication_rejects_reparse_parent_before_temp_creation(tmp_path: Path) -> None:
    import tools.promin_client_report as module

    real_parent = tmp_path / "real"
    real_parent.mkdir()
    reparse_parent = tmp_path / "reparse"
    try:
        reparse_parent.symlink_to(real_parent, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory reparse/symlink creation unavailable")

    with pytest.raises(ClientReportToolError, match="real directory"):
        publish_evidence_packet(
            _publication_packet(),
            reparse_parent / "report.json",
            reparse_parent / "report.pdf",
            reparse_parent / "receipt.json",
        )
    assert not list(real_parent.glob(".*.tmp"))


def test_client_report_cli_parse_failure_is_bounded(capsys: pytest.CaptureFixture[str]) -> None:
    result = main(["--unknown-option", "x" * 12000])
    captured = capsys.readouterr()
    assert result == 2
    assert len(captured.err.encode("utf-8")) <= 600
    assert "usage:" not in captured.err.casefold()


def test_client_report_cli_validation_failure_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import tools.promin_client_report as module

    monkeypatch.setattr(module, "build_evidence_packet", lambda *_args: (_ for _ in ()).throw(ClientReportToolError("validation failure " + "x" * 10000)))
    result = main([
        "--inspection", str(tmp_path / "inspection.json"),
        "--saturation-root", str(tmp_path),
        "--candidate-binding", str(tmp_path / "candidate.json"),
        "--comparative", str(tmp_path / "comparative.json"),
        "--report-out", str(tmp_path / "report.json"),
        "--pdf-out", str(tmp_path / "report.pdf"),
        "--receipt-out", str(tmp_path / "receipt.json"),
    ])
    captured = capsys.readouterr()
    assert result == 2
    assert len(captured.err.encode("utf-8")) <= 600
    assert not (tmp_path / "receipt.json").exists()


def test_client_report_cli_render_failure_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import tools.promin_client_report as module

    monkeypatch.setattr(module, "build_evidence_packet", lambda *_args: _publication_packet())
    monkeypatch.setattr(module, "_build_evidence_pdf", lambda *_args: (_ for _ in ()).throw(RuntimeError("render failure " + "x" * 10000)))
    result = main([
        "--inspection", str(tmp_path / "inspection.json"),
        "--saturation-root", str(tmp_path),
        "--candidate-binding", str(tmp_path / "candidate.json"),
        "--comparative", str(tmp_path / "comparative.json"),
        "--report-out", str(tmp_path / "report.json"),
        "--pdf-out", str(tmp_path / "report.pdf"),
        "--receipt-out", str(tmp_path / "receipt.json"),
    ])
    captured = capsys.readouterr()
    assert result == 2
    assert len(captured.err.encode("utf-8")) <= 600
    assert not (tmp_path / "receipt.json").exists()


def test_client_report_cli_collision_failure_is_bounded_and_preserves_sentinel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import tools.promin_client_report as module

    sentinel = tmp_path / "report.json"
    sentinel.write_bytes(b"sentinel")
    monkeypatch.setattr(module, "build_evidence_packet", lambda *_args: _publication_packet())
    result = main([
        "--inspection", str(tmp_path / "inspection.json"),
        "--saturation-root", str(tmp_path),
        "--candidate-binding", str(tmp_path / "candidate.json"),
        "--comparative", str(tmp_path / "comparative.json"),
        "--report-out", str(sentinel),
        "--pdf-out", str(tmp_path / "report.pdf"),
        "--receipt-out", str(tmp_path / "receipt.json"),
    ])
    captured = capsys.readouterr()
    assert result == 2
    assert len(captured.err.encode("utf-8")) <= 600
    assert sentinel.read_bytes() == b"sentinel"
    assert not (tmp_path / "receipt.json").exists()


def test_direct_script_help_ignores_hostile_tools_shadow(tmp_path: Path) -> None:
    hostile = tmp_path / "hostile"
    (hostile / "tools").mkdir(parents=True)
    (hostile / "tools" / "promin.py").write_text("raise RuntimeError('shadowed')\n", encoding="utf-8")
    script = Path(__file__).parents[1] / "tools" / "promin_client_report.py"
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(hostile)
    result = subprocess.run(
        [sys.executable, "-B", str(script), "--help"],
        cwd=hostile,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "Publish a canonical Promin Windows evidence packet" in result.stdout
    assert "shadowed" not in result.stderr
