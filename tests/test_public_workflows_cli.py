from __future__ import annotations

import base64
from pathlib import Path

import pytest

from promin.__main__ import _next_initial_project_work, _parser, _run
from promin.canonical import canonical_bytes, digest_bytes, digest_value
from promin.init_profiles import export_expert_init_bundle, load_init_profile
from promin.recovery import (
    CleanReinitializationIntent,
    OwnerConfirmation,
    PublishedCleanReinitialization,
    TrackedExtensionRoot,
    admit_clean_state,
    admit_tracked_extensions,
)
from promin.revalidation import RevalidationPhase, RevalidationPlan
from promin.revalidation_workflow import (
    REVALIDATION_WORKFLOW_PHASE_SEQUENCE,
    RevalidationWorkflowAuthority,
    RevalidationWorkflowMode,
    RevalidationWorkflowPlan,
    RevalidationWorkflowReceipt,
    execute_revalidation_workflow,
)
from promin.service import BASE_COMMANDS, ServiceError
from promin.writer_identity import classify_writer_liveness


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
CLAIM_FIELDS = {
    "acceptance_pass",
    "authority_granted",
    "pass_credit",
    "product_acceptance_pass",
}


def _args(root: Path, *values: str):
    return _parser().parse_args(
        ["--root", str(root), "--no-telemetry", *values]
    )


def _write(path: Path, value: object) -> Path:
    path.write_bytes(canonical_bytes(value))
    return path


def _assert_false_claims(value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in CLAIM_FIELDS:
                assert child is False, key
            if key == "authority" and isinstance(child, bool):
                assert child is False
            _assert_false_claims(child)
    elif isinstance(value, list):
        for child in value:
            _assert_false_claims(child)


def _expert_selection() -> dict[str, object]:
    return {
        "python": {
            "capability_id": "python-language",
            "documentation": [
                "python-documentation-generator",
                "python-language-reference",
            ],
            "tools": ["python-static-analysis", "python-compile-check"],
        }
    }


def _weak_plan() -> dict[str, object]:
    return {
        "schema": "promin.high-level-execution-plan.v1",
        "plan_id": "cli-worker",
        "budget": {
            "max_high_level_tasks": 2,
            "max_executor_tasks": 6,
            "max_dependencies_per_task": 2,
            "max_allowed_paths_per_task": 2,
            "max_static_tools_per_task": 2,
            "max_task_instruction_bytes": 1024,
            "max_task_output_bytes": 256,
            "max_attempts_per_task": 2,
            "max_parallel_tasks": 1,
        },
        "tasks": [
            {
                "task_id": "inspect-source",
                "title": "Inspect one source",
                "objective": "Read the declared bounded source.",
                "allowed_paths": ["promin/example.py"],
                "dependencies": [],
                "risk_class": "read-only",
                "static_tool_ids": ["source-scan"],
                "acceptance_predicate": "The observation is reviewable.",
            }
        ],
    }


def _route() -> dict[str, object]:
    identity = {
        "activation_identity": digest_value({"activation": "cli"}),
        "acceptance_pass": False,
        "pass_credit": False,
    }
    plan = RevalidationPlan(
        plan_id="cli-revalidation",
        input_identity=identity,
        phases=(RevalidationPhase("authority", 2.0),),
    )
    return {
        "plan_id": plan.plan_id,
        "input_identity": identity,
        "phases": [{"phase_id": "authority", "budget_seconds": 2.0}],
        "total_budget_seconds": plan.total_budget_seconds,
        "prior_receipts": [],
        "max_phases": None,
    }


def _revalidation_request(
    root: Path,
    *,
    mode: str,
    name: str,
    route: dict[str, object] | None = None,
    report_receipt: str | None = None,
    repair: object = None,
    execution: dict[str, object] | None = None,
    predecessor_receipt: str | None = None,
) -> dict[str, object]:
    return {
        "schema": "promin.revalidation-cli-input.v1",
        "record_type": "RevalidationCliInput",
        "workflow_id": "cli-cycle",
        "mode": mode,
        "authority": {
            "authority_id": "owner:cli",
            "implementation_digest": digest_value({"implementation": "cli"}),
            "configuration_digest": digest_value({"configuration": "cli"}),
        },
        "receipt_root": str(root),
        "receipt_name": name,
        "retry_ordinal": 1,
        "predecessor_receipt": predecessor_receipt,
        "revalidation": route,
        "report_receipt": report_receipt,
        "repair": repair,
        "execution": execution,
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }


def _repair_predecessor(
    tmp_path: Path,
    receipts: Path,
    inspected: RevalidationWorkflowReceipt,
) -> RevalidationWorkflowReceipt:
    source = tmp_path / "extension-source"
    tracked = source / ".promin" / "docs"
    tracked.mkdir(parents=True)
    (tracked / "note.md").write_text("ordinary extension\n", encoding="utf-8")
    extension = admit_tracked_extensions(
        source,
        (TrackedExtensionRoot(".promin/docs", 2, 256, 128),),
    )
    intent = CleanReinitializationIntent(
        project_identity=digest_value({"project": "cli"}),
        package_digest=digest_value({"package": "cli"}),
        profile_id="minimal",
        extension_admission_digest=extension.admission_digest,
    )
    admission = admit_clean_state(
        intent,
        OwnerConfirmation(
            owner_id="owner:cli",
            confirmation_id="confirmation:cli",
            intent_digest=intent.intent_digest,
            confirmed_at_ns=1,
        ),
        extension,
    )
    existing = PublishedCleanReinitialization(
        intent_digest=intent.intent_digest,
        package_digest=intent.package_digest,
        extension_admission_digest=intent.extension_admission_digest,
        activation_digest=digest_value({"activation": "cli"}),
    )
    project = tmp_path / "project"
    project.mkdir()
    plan = RevalidationWorkflowPlan(
        workflow_id="cli-cycle",
        mode=RevalidationWorkflowMode.REPAIR,
        authority=RevalidationWorkflowAuthority(
            authority_id="owner:cli",
            implementation_digest=digest_value({"implementation": "cli"}),
            configuration_digest=digest_value({"configuration": "cli"}),
        ),
        receipt_root=receipts,
        receipt_name="repair.json",
        predecessor_receipt_digest=inspected.receipt_digest,
        predecessor_receipt=inspected,
        repair_project_root=project,
        repair_admission=admission,
        repair_writer_liveness=classify_writer_liveness(None),
        repair_existing=existing,
        max_attempts=1,
    )
    return execute_revalidation_workflow(
        plan,
        repair_verifier=lambda _candidate: True,
        repair_attempt=lambda _transaction, _ordinal: existing,
    )


def test_parser_keeps_base_commands_and_thin_nested_selectors(tmp_path: Path) -> None:
    parser = _parser()
    choices = next(
        action.choices
        for action in parser._actions
        if isinstance(getattr(action, "choices", None), dict)
    )
    assert tuple(choices) == BASE_COMMANDS
    assert _args(tmp_path, "init", "--expert-bundle", "bundle").expert_bundle
    assert _args(tmp_path, "next", "--initial-work", "plan").initial_work == "plan"
    for action in (
        "prepare",
        "review",
        "resume",
        "record",
        "pause",
        "resume-task",
        "cancel",
        "owner-decision",
        "recover-interrupted",
    ):
        assert _args(tmp_path, "next", "--weak-work", action).weak_work == action
    next_help = choices["next"].format_help()
    for action in (
        "pause",
        "resume-task",
        "cancel",
        "owner-decision",
        "recover-interrupted",
    ):
        assert action in next_help
    assert (
        _args(tmp_path, "next", "--weak-decision", "APPROVED").weak_decision
        == "APPROVED"
    )
    assert _args(tmp_path, "next", "--weak-confirm-stopped").weak_confirm_stopped
    assert _args(tmp_path, "doctor", "--revalidate", "input").revalidate
    assert _args(
        tmp_path,
        "doctor",
        "--revalidate",
        "input",
        "--execute-revalidation",
    ).execute_revalidation
    with pytest.raises(SystemExit):
        parser.parse_args(["doctor", "--repair", "--revalidate", "input"])


def test_expert_bundle_is_one_configuration_authority(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    bundle = tmp_path / "bundle"
    inputs = {
        "goal": "Inspect the bounded project",
        "autonomy": "standing-reversible",
        "reporting_language": "en",
        "profile_layers": ["general-development", "standing-reversible", "en"],
        "brief": {
            "constraints": ["no network"],
            "deliverables": ["diagnostic evidence"],
        },
        "max_preflight_files": 32,
    }
    exported = export_expert_init_bundle(
        bundle,
        standard_default=load_init_profile(
            PACKAGE_ROOT / "capability_profiles" / "standard-init.json"
        ),
        plan_inputs=inputs,
        languages=("python",),
        expert_selections=_expert_selection(),
        expert_source="owner",
    )
    assert exported["record_type"] == "ExpertInit"
    assert exported["bundle_file"] == "expert-init.json"
    assert {path.name for path in bundle.iterdir()} == {"expert-init.json"}
    assert set(exported["expert_selections"]) == {"python-semantic"}

    result = _run(_args(project, "init", "--expert-bundle", str(bundle)))

    assert result["expert_init_bundle"]["bundle_digest"] == exported["bundle_digest"]
    assert result["expert_init_bundle"]["plan_inputs"] == inputs
    assert result["resolved_plan"]["goal"] == inputs["goal"]
    assert result["resolved_plan"]["profile_layers"] == inputs["profile_layers"]
    assert result["resolved_plan"]["constraints"] == ["no network"]
    _assert_false_claims(result)

    with pytest.raises(ServiceError, match="cannot be combined"):
        _run(
            _args(
                project,
                "init",
                "--expert-bundle",
                str(bundle),
                "--goal",
                "competing goal",
            )
        )


def test_ordinary_init_and_next_do_not_start_optional_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import promin.__main__ as cli
    import promin.initial_project_work as initial_work

    monkeypatch.setattr(
        cli,
        "apply_plan",
        lambda _root, _plan: {
            "record_type": "InitializationResult",
            "status": "initialized",
            "authority": False,
            "pass_credit": False,
        },
    )
    monkeypatch.setattr(
        initial_work,
        "prepare_initial_project_work",
        lambda *_args, **_kwargs: pytest.fail("optional initial work was invoked"),
    )
    proposal = {
        "record_type": "SuggestedWorkCard",
        "status": "PENDING_PACKAGE_DEFINED_WORK_CARD",
        "authority": False,
        "pass_credit": False,
    }
    monkeypatch.setattr(cli, "next_proposal", lambda _root: proposal)

    initialized = _run(_args(tmp_path, "init", "--yes"))
    suggested = _run(_args(tmp_path, "next"))

    assert initialized["record_type"] == "InitializationResult"
    assert suggested == proposal
    _assert_false_claims(initialized)
    _assert_false_claims(suggested)


@pytest.mark.parametrize(
    ("filename", "language", "profile_id"),
    (
        ("source.kt", "kotlin", "jvm-semantic"),
        ("source.ts", "typescript", "javascript-typescript-semantic"),
    ),
)
def test_minimal_init_preserves_detected_language_identity_from_catalog(
    tmp_path: Path, filename: str, language: str, profile_id: str
) -> None:
    project = tmp_path / language
    project.mkdir()
    (project / filename).write_text("ordinary source\n", encoding="utf-8")

    result = _run(_args(project, "init"))

    experience = result["init_experience"]
    assert experience["languages"] == [language]
    assert [
        selection["profile_id"]
        for selection in experience["capability_selections"]
    ] == [profile_id]
    _assert_false_claims(result)


def test_initial_work_requires_an_explicit_plan_or_execute_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import promin.__main__ as cli
    import promin.initial_project_work as initial_work

    calls: list[bool] = []
    monkeypatch.setattr(cli, "_require_initialized", lambda _root: None)
    monkeypatch.setattr(cli, "load_resolved_plan", lambda _root: {"plan": "bound"})

    def prepare(_root, _plan, *, execute=False):
        calls.append(execute)
        return {
            "record_type": "InitialProjectWorkResult",
            "authority": False,
            "pass_credit": False,
            "acceptance_pass": False,
            "product_acceptance_pass": False,
        }

    monkeypatch.setattr(initial_work, "prepare_initial_project_work", prepare)

    _run(_args(tmp_path, "next", "--initial-work", "plan"))
    _next_initial_project_work(tmp_path, execute=True)

    assert calls == [False, True]
    with pytest.raises(ServiceError, match="strict Core next"):
        _run(_args(tmp_path, "next", "--initial-work", "plan", "--depth", "2"))


def test_weak_work_records_only_explicit_canonical_outcome(tmp_path: Path) -> None:
    source = _write(tmp_path / "plan.json", _weak_plan())
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    prepared = _run(
        _args(tmp_path, "next", "--weak-work", "prepare", "--weak-input", str(source))
    )
    assert [card["task_id"] for card in prepared["tasks"]] == [
        "inspect-source:execute"
    ]
    reviewed = _run(
        _args(
            tmp_path,
            "next",
            "--weak-work",
            "review",
            "--weak-input",
            str(source),
            "--weak-receipts",
            str(receipts),
        )
    )
    output = b"bounded observation\n"
    outcome = {
        "schema": "promin.weak-model-recorded-outcome.v1",
        "record_type": "WeakModelRecordedOutcome",
        "workflow_digest": digest_value(prepared),
        "receipt_set_digest": reviewed["receipt_set_digest"],
        "task_id": "inspect-source:execute",
        "attempt": 1,
        "status": "COMPLETED",
        "output_base64": base64.b64encode(output).decode("ascii"),
        "output_bytes": len(output),
        "output_sha256": digest_bytes(output),
        "observation": "The caller supplied one bounded observation.",
        "current_authorization_confirmed": False,
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }
    outcome_path = _write(tmp_path / "outcome.json", outcome)

    recorded = _run(
        _args(
            tmp_path,
            "next",
            "--weak-work",
            "record",
            "--weak-input",
            str(source),
            "--weak-receipts",
            str(receipts),
            "--weak-task-id",
            "inspect-source:execute",
            "--weak-outcome",
            str(outcome_path),
        )
    )
    resumed = _run(
        _args(
            tmp_path,
            "next",
            "--weak-work",
            "resume",
            "--weak-input",
            str(source),
            "--weak-receipts",
            str(receipts),
        )
    )

    assert recorded["status"] == "COMPLETED"
    assert recorded["output_digest"] == digest_bytes(output)
    assert resumed["ready_task_ids"] == []
    _assert_false_claims(recorded)
    _assert_false_claims(resumed)
    assert resumed["workflow_state"] == "COMPLETED"

    promoted = dict(outcome)
    promoted["pass_credit"] = True
    promoted_path = _write(tmp_path / "promoted.json", promoted)
    with pytest.raises(ServiceError, match="pass_credit must remain false"):
        _run(
            _args(
                tmp_path,
                "next",
                "--weak-work",
                "record",
                "--weak-input",
                str(source),
                "--weak-receipts",
                str(receipts),
                "--weak-task-id",
                "inspect-source:execute",
                "--weak-outcome",
                str(promoted_path),
            )
        )


def test_weak_work_controls_delegate_to_public_lifecycle(tmp_path: Path) -> None:
    source = _write(tmp_path / "control-plan.json", _weak_plan())
    receipts = tmp_path / "control-receipts"
    receipts.mkdir()
    common = (
        "next",
        "--weak-input",
        str(source),
        "--weak-receipts",
        str(receipts),
        "--weak-task-id",
        "inspect-source:execute",
    )

    paused = _run(_args(tmp_path, *common, "--weak-work", "pause"))
    assert paused["action"] == "PAUSE"
    assert paused["target_state"] == "BLOCKED"
    reviewed = _run(
        _args(
            tmp_path,
            "next",
            "--weak-work",
            "review",
            "--weak-input",
            str(source),
            "--weak-receipts",
            str(receipts),
        )
    )
    assert reviewed["workflow_state"] == "ACTIVE"
    assert reviewed["task_states"][0]["block_reason"] == "pause-requested"

    resumed = _run(_args(tmp_path, *common, "--weak-work", "resume-task"))
    assert resumed["action"] == "RESUME"
    assert resumed["target_state"] == "READY"
    cancelled = _run(_args(tmp_path, *common, "--weak-work", "cancel"))
    assert cancelled["action"] == "CANCEL"
    assert cancelled["target_state"] == "CANCELLED"
    final = _run(
        _args(
            tmp_path,
            "next",
            "--weak-work",
            "resume",
            "--weak-input",
            str(source),
            "--weak-receipts",
            str(receipts),
        )
    )
    assert final["workflow_state"] == "CANCELLED"
    for record in (paused, reviewed, resumed, cancelled, final):
        _assert_false_claims(record)


def test_weak_work_owner_decision_is_explicit(tmp_path: Path) -> None:
    plan = _weak_plan()
    plan["tasks"][0]["risk_class"] = "owner-only"
    source = _write(tmp_path / "decision-plan.json", plan)

    for decision, state in (("APPROVED", "ACTIVE"), ("DECLINED", "CANCELLED")):
        receipts = tmp_path / decision.casefold()
        receipts.mkdir()
        result = _run(
            _args(
                tmp_path,
                "next",
                "--weak-work",
                "owner-decision",
                "--weak-input",
                str(source),
                "--weak-receipts",
                str(receipts),
                "--weak-task-id",
                "inspect-source:execute",
                "--weak-decision",
                decision,
            )
        )
        reviewed = _run(
            _args(
                tmp_path,
                "next",
                "--weak-work",
                "review",
                "--weak-input",
                str(source),
                "--weak-receipts",
                str(receipts),
            )
        )
        assert result["decision"] == decision
        assert reviewed["workflow_state"] == state
        _assert_false_claims(result)
        _assert_false_claims(reviewed)


def test_weak_work_recovers_only_explicitly_confirmed_stopped_attempt(
    tmp_path: Path,
) -> None:
    from promin.weak_model_workflow import execute, prepare

    source = _write(tmp_path / "interrupted-plan.json", _weak_plan())
    receipts = tmp_path / "interrupted-receipts"
    receipts.mkdir()
    workflow = prepare(_weak_plan())

    with pytest.raises(KeyboardInterrupt):
        execute(
            workflow,
            receipts,
            task_id="inspect-source:execute",
            executor=lambda _request: (_ for _ in ()).throw(KeyboardInterrupt),
        )

    recovered = _run(
        _args(
            tmp_path,
            "next",
            "--weak-work",
            "recover-interrupted",
            "--weak-input",
            str(source),
            "--weak-receipts",
            str(receipts),
            "--weak-task-id",
            "inspect-source:execute",
            "--weak-confirm-stopped",
        )
    )
    assert recovered["task_id"] == "inspect-source:execute"
    assert recovered["status"] == "BLOCKED"
    assert recovered["attempt_outcome"] == "INTERRUPTED"
    assert recovered["block_reason"] == "executor-interrupted"
    _assert_false_claims(recovered)


def test_nested_inputs_are_exact_canonical_json(tmp_path: Path) -> None:
    path = tmp_path / "noncanonical.json"
    path.write_bytes(canonical_bytes(_weak_plan()) + b"\n")

    with pytest.raises(ServiceError, match="exact canonical JSON object"):
        _run(
            _args(
                tmp_path,
                "next",
                "--weak-work",
                "prepare",
                "--weak-input",
                str(path),
            )
        )


def test_revalidation_plan_and_read_only_modes_are_explicit(tmp_path: Path) -> None:
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    route = _route()
    planned_path = _write(
        tmp_path / "inspect-plan.json",
        _revalidation_request(
            receipts,
            mode="inspect",
            name="inspect-plan.json",
            route=route,
        ),
    )

    planned = _run(
        _args(tmp_path, "doctor", "--revalidate", str(planned_path))
    )

    assert planned["plan_only"] is True
    assert planned["filesystem_writes"] == 0
    assert not (receipts / "inspect-plan.json").exists()

    inspect_path = _write(
        tmp_path / "inspect.json",
        _revalidation_request(
            receipts,
            mode="inspect",
            name="inspect-receipt.json",
            route=route,
            execution={"kind": "no-callbacks"},
        ),
    )
    inspected = _run(
        _args(
            tmp_path,
            "doctor",
            "--revalidate",
            str(inspect_path),
            "--execute-revalidation",
        )
    )
    assert inspected["result_kind"] == "RevalidationWorkflowInspection"
    inspected_receipt = RevalidationWorkflowReceipt.from_record(inspected)
    repaired = _repair_predecessor(tmp_path, receipts, inspected_receipt)

    unavailable_path = _write(
        tmp_path / "unavailable.json",
        _revalidation_request(
            receipts,
            mode="revalidate",
            name="revalidated.json",
            route=route,
            predecessor_receipt=str(receipts / "repair.json"),
            execution={
                "kind": "recorded-read-only-observations",
                "observations": [
                    {
                        "phase_id": "authority",
                        "status": "UNAVAILABLE",
                        "observed_input_digest": "0" * 64,
                        "output_identity": {
                            "observation": "authority unavailable",
                            "acceptance_pass": False,
                            "pass_credit": False,
                        },
                        "reason": "authority unavailable",
                    }
                ],
            },
        ),
    )
    revalidated = _run(
        _args(
            tmp_path,
            "doctor",
            "--revalidate",
            str(unavailable_path),
            "--execute-revalidation",
        )
    )
    assert revalidated["result_kind"] == "RevalidationReceipt"

    prior_route = dict(route)
    prior_route["prior_receipts"] = [str(receipts / "revalidated.json")]
    reconsolidate_path = _write(
        tmp_path / "reconsolidate.json",
        _revalidation_request(
            receipts,
            mode="reconsolidate",
            name="reconsolidated.json",
            route=prior_route,
            predecessor_receipt=str(receipts / "revalidated.json"),
            execution={"kind": "no-callbacks"},
        ),
    )
    reconsolidated = _run(
        _args(
            tmp_path,
            "doctor",
            "--revalidate",
            str(reconsolidate_path),
            "--execute-revalidation",
        )
    )
    assert reconsolidated["result_kind"] == "RevalidationReceipt"

    report_path = _write(
        tmp_path / "report.json",
        _revalidation_request(
            receipts,
            mode="report",
            name="report-receipt.json",
            report_receipt=str(receipts / "reconsolidated.json"),
            predecessor_receipt=str(receipts / "reconsolidated.json"),
            execution={"kind": "no-callbacks"},
        ),
    )
    report = _run(
        _args(
            tmp_path,
            "doctor",
            "--revalidate",
            str(report_path),
            "--execute-revalidation",
        )
    )
    assert report["result_kind"] == "RevalidationReportPreparation"
    chain = (inspected, repaired.to_record(), revalidated, reconsolidated, report)
    assert tuple(item["mode"] for item in chain) == REVALIDATION_WORKFLOW_PHASE_SEQUENCE
    assert [item["transition_kind"] for item in chain] == [
        "START",
        "ADVANCE",
        "ADVANCE",
        "ADVANCE",
        "ADVANCE",
    ]
    assert len({item["workflow_semantic_digest"] for item in chain}) == 1
    for result in (planned, inspected, revalidated, reconsolidated, report):
        _assert_false_claims(result)


def test_revalidation_rejects_recorded_pass_false_claims_and_cli_repair(
    tmp_path: Path,
) -> None:
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    route = _route()
    inspect_path = _write(
        tmp_path / "pass-inspect-input.json",
        _revalidation_request(
            receipts,
            mode="inspect",
            name="pass-inspect.json",
            route=route,
            execution={"kind": "no-callbacks"},
        ),
    )
    inspected = RevalidationWorkflowReceipt.from_record(
        _run(
            _args(
                tmp_path,
                "doctor",
                "--revalidate",
                str(inspect_path),
                "--execute-revalidation",
            )
        )
    )
    _repair_predecessor(tmp_path, receipts, inspected)
    recorded_pass = _revalidation_request(
        receipts,
        mode="revalidate",
        name="pass.json",
        route=route,
        predecessor_receipt=str(receipts / "repair.json"),
        execution={
            "kind": "recorded-read-only-observations",
            "observations": [
                {
                    "phase_id": "authority",
                    "status": "PASS",
                    "observed_input_digest": "0" * 64,
                    "output_identity": {
                        "observation": "imported pass",
                        "acceptance_pass": False,
                        "pass_credit": False,
                    },
                    "reason": None,
                }
            ],
        },
    )
    pass_path = _write(tmp_path / "pass.json", recorded_pass)
    with pytest.raises(ServiceError, match="cannot assert PASS"):
        _run(
            _args(
                tmp_path,
                "doctor",
                "--revalidate",
                str(pass_path),
                "--execute-revalidation",
            )
        )

    promoted = _revalidation_request(
        receipts,
        mode="inspect",
        name="promoted.json",
        route=route,
    )
    promoted["acceptance_pass"] = True
    promoted_path = _write(tmp_path / "promoted.json", promoted)
    with pytest.raises(ServiceError, match="acceptance_pass must remain false"):
        _run(_args(tmp_path, "doctor", "--revalidate", str(promoted_path)))

    repair_path = _write(
        tmp_path / "repair.json",
        _revalidation_request(
            receipts,
            mode="repair",
            name="repair.json",
            repair={},
        ),
    )
    with pytest.raises(ServiceError, match="explicit public workflow API"):
        _run(_args(tmp_path, "doctor", "--revalidate", str(repair_path)))
    with pytest.raises(ServiceError, match="requires --revalidate"):
        _run(_args(tmp_path, "doctor", "--execute-revalidation"))


def test_nested_modes_reject_ignored_inputs(tmp_path: Path) -> None:
    source = _write(tmp_path / "plan.json", _weak_plan())

    with pytest.raises(ServiceError, match="require --weak-work"):
        _run(_args(tmp_path, "next", "--weak-input", str(source)))
    with pytest.raises(ServiceError, match="strict Core next"):
        _run(
            _args(
                tmp_path,
                "next",
                "--weak-work",
                "prepare",
                "--weak-input",
                str(source),
                "--depth",
                "2",
            )
        )
    with pytest.raises(ServiceError, match="accepts only --weak-input"):
        _run(
            _args(
                tmp_path,
                "next",
                "--weak-work",
                "prepare",
                "--weak-input",
                str(source),
                "--weak-receipts",
                str(tmp_path),
            )
        )
    with pytest.raises(ServiceError, match="requires only --weak-task-id"):
        _run(
            _args(
                tmp_path,
                "next",
                "--weak-work",
                "pause",
                "--weak-input",
                str(source),
                "--weak-receipts",
                str(tmp_path),
            )
        )
    with pytest.raises(ServiceError, match="requires --weak-task-id and --weak-decision"):
        _run(
            _args(
                tmp_path,
                "next",
                "--weak-work",
                "owner-decision",
                "--weak-input",
                str(source),
                "--weak-receipts",
                str(tmp_path),
                "--weak-task-id",
                "inspect-source:execute",
            )
        )
    with pytest.raises(
        ServiceError,
        match="requires --weak-task-id and --weak-confirm-stopped",
    ):
        _run(
            _args(
                tmp_path,
                "next",
                "--weak-work",
                "recover-interrupted",
                "--weak-input",
                str(source),
                "--weak-receipts",
                str(tmp_path),
                "--weak-task-id",
                "inspect-source:execute",
            )
        )
