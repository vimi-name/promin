from __future__ import annotations

import json
from pathlib import Path

from promin import __main__ as cli
from promin.client_report import report_from_inspection
from promin.canonical import digest_value
from promin.product_inspection import inspect_product
from promin.revalidation import RevalidationPhase, RevalidationPlan
from promin.revalidation_workflow import (
    RevalidationWorkflowAuthority,
    RevalidationWorkflowMode,
    RevalidationWorkflowPlan,
    plan_revalidation_workflow,
)


def _json_stdout(capsys) -> dict[str, object]:
    return json.loads(capsys.readouterr().out)


def test_public_minimal_init_plan_is_configured_but_non_crediting(tmp_path: Path, capsys) -> None:
    (tmp_path / "tool.py").write_text("print('ok')\n", encoding="utf-8")

    assert cli.main(
        [
            "--root",
            str(tmp_path),
            "--no-telemetry",
            "init",
            "--plan-only",
        ]
    ) == 0

    result = _json_stdout(capsys)
    assert result["status"] == "review-required"
    experience = result["init_experience"]
    assert experience["experience"] == "minimal"
    assert experience["status"] == "CONFIGURED_PENDING_HOST_OBSERVATION"
    assert experience["languages"] == ["python"]
    assert experience["host_probe_performed"] is False
    assert experience["authority_granted"] is False
    assert experience["pass_credit"] is False
    assert experience["acceptance_pass"] is False


def test_public_expert_init_requires_and_binds_registered_selection(tmp_path: Path, capsys) -> None:
    selections = tmp_path / "expert-selections.json"
    selections.write_text(
        json.dumps(
            {
                "python": {
                    "capability_id": "python-language",
                    "documentation": [
                        "python-language-reference",
                        "python-documentation-generator",
                    ],
                    "tools": ["python-compile-check", "python-static-analysis"],
                }
            }
        ),
        encoding="utf-8",
    )

    assert cli.main(
        [
            "--root",
            str(tmp_path),
            "--no-telemetry",
            "init",
            "--init-experience",
            "expert",
            "--capability-language",
            "python",
            "--capability-selections",
            str(selections),
            "--plan-only",
        ]
    ) == 0

    result = _json_stdout(capsys)
    experience = result["init_experience"]
    assert experience["experience"] == "expert"
    assert experience["capability_selection_source"] == "cli"
    selected = experience["capability_selections"][0]
    assert selected["profile_id"] == "python-semantic"
    assert selected["authority_granted"] is False
    assert selected["pass_credit"] is False
    assert selected["acceptance_pass"] is False


def test_revalidation_plan_and_report_preparation_are_deterministic_and_non_crediting(
    tmp_path: Path,
) -> None:
    route = RevalidationPlan(
        plan_id="init-layer-route",
        input_identity={
            "activation_identity": digest_value({"activation": 1}),
            "recovery_identity": digest_value({"recovery": 1}),
            "acceptance_pass": False,
            "pass_credit": False,
        },
        phases=(RevalidationPhase("inventory", 1.0),),
    )
    authority = RevalidationWorkflowAuthority(
        authority_id="owner:init-layer",
        implementation_digest=digest_value({"implementation": 1}),
        configuration_digest=digest_value({"configuration": 1}),
    )
    first = RevalidationWorkflowPlan(
        workflow_id="init-layer-cycle",
        mode=RevalidationWorkflowMode.INSPECT,
        authority=authority,
        receipt_root=tmp_path,
        receipt_name="first.json",
        revalidation_plan=route,
    )
    second = RevalidationWorkflowPlan(
        workflow_id="init-layer-cycle",
        mode=RevalidationWorkflowMode.INSPECT,
        authority=authority,
        receipt_root=tmp_path,
        receipt_name="first.json",
        revalidation_plan=route,
    )
    assert plan_revalidation_workflow(first)["plan_digest"] == plan_revalidation_workflow(
        second
    )["plan_digest"]

    (tmp_path / "module.py").write_text("value = 1\n", encoding="utf-8")
    inspection = inspect_product(tmp_path)
    report = report_from_inspection(inspection)
    assert report["schema"] == "promin.client-report.v1"
    assert all(value is False for value in report["claims"].values())
    assert report["inspection"]["claims"]["runtime_validated"] is False
