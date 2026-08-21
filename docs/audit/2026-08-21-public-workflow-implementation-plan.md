# Public Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make minimal initialization, bounded first-work preparation, product inspection, clean recovery, revalidation, and client-safe JSON reporting discoverable public Promin CLI workflows.

**Architecture:** The CLI remains a thin adapter over the existing domain owners. `initial_project_work` remains the owner of the bounded proposal artifact; `clean_reinitialization` remains the owner of quarantine/rollback; `revalidation_workflow` remains the owner of receipt sequencing; and `product_inspection` remains the owner of static facts. New CLI helpers only parse strict input, call those owners, and render canonical JSON.

**Tech Stack:** Python 3.13, argparse, canonical JSON, existing Promin EventStore and receipt APIs, pytest.

**Spec:** `docs/audit/2026-08-21-public-workflow-and-tooling-design.md`

## Global Constraints

- Keep `VERSION.json` and published version `1.0.0-alpha.4` unchanged.
- Keep all acceptance, pass-credit, performance, platform, and release claims false unless an existing owner independently proves them.
- Do not install software, download packages, invoke models, or auto-run external tools from the public workflow slice.
- Public paths must reject non-canonical paths, unknown fields, stale receipt bindings, and missing authority before state mutation.
- `init --yes` may prepare bounded Promin evidence but must never mutate project source or execute a proposed task.
- Preserve r6, r7, r8, and all interrupted r9 evidence roots; no test may read, reuse, restart, or delete them.
- Executors do not commit. The integrator makes one final same-version commit only after focused tests, inventory refresh, strict integrity verification, and diff review.

---

### Task 1: Join guided init to the bounded first-work route

**Files:**
- Modify: `promin/__main__.py:58-118,580-680,1128-1137`
- Test: `tests/test_public_workflows_cli.py`
- Test: `tests/test_initial_project_work.py`

**Interfaces:**
- Consumes: `prepare_initial_project_work(project_root, resolved_plan, execute: bool, max_files: int, max_bytes: int) -> dict[str, Any]` from `promin.initial_project_work`.
- Produces: CLI `promin init --initial-work {none,plan,prepare}` and an `InitResult` field named `initial_work`.
- Invariant: only `prepare` calls `prepare_initial_project_work(..., execute=True)` after `apply_plan` succeeds; `plan` does not apply init; `none` preserves current behavior.

- [ ] **Step 1: Write the failing public CLI tests**

```python
def test_minimal_init_prepare_publishes_only_bounded_first_work(tmp_path, capsys):
    assert main([
        "--root", str(tmp_path), "--no-telemetry", "init",
        "--goal", "organize docs", "--init-experience", "minimal",
        "--yes", "--initial-work", "prepare",
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["initial_work"]["status"] == "READY_PROPOSAL_ONLY"
    assert result["initial_work"]["project_mutation_performed"] is False
    assert result["acceptance_pass"] is False
    assert not (tmp_path / "README.md").exists()

def test_init_plan_initial_work_never_creates_control_state(tmp_path, capsys):
    assert main(["--root", str(tmp_path), "init", "--initial-work", "plan"]) == 0
    assert not (tmp_path / ".promin").exists()
```

- [ ] **Step 2: Run the tests to prove the option is absent**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_public_workflows_cli.py -k initial_work`

Expected: FAIL because `init` rejects `--initial-work`.

- [ ] **Step 3: Add the explicit parser option and a narrow dispatch helper**

```python
init.add_argument(
    "--initial-work",
    choices=("none", "plan", "prepare"),
    default=None,
    help="bind bounded first-work proposal generation to this init request",
)

def _initial_work_after_init(root: Path, plan: Mapping[str, Any], mode: str) -> dict[str, Any] | None:
    if mode == "none":
        return None
    return prepare_initial_project_work(root, plan, execute=(mode == "prepare"))
```

In `_guided_init`, resolve default `prepare` only when `args.apply` and the
guided capability mode is `minimal`; keep expert mode explicit and pass the
same bound `plan` to the helper. Attach the result under `initial_work` only
after a successful `apply_plan`.

- [ ] **Step 4: Run the focused init and first-work suites**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_public_workflows_cli.py tests/test_initial_project_work.py tests/test_heavy_init_profiles.py`

Expected: PASS; a failed/truncated inventory keeps its existing false claims
and does not cause source mutation.

### Task 2: Add public bounded inspection and client-safe JSON report commands

**Files:**
- Modify: `promin/__main__.py:136-180,1216-1255`
- Create: `promin/client_report.py`
- Test: `tests/test_public_workflows_cli.py`
- Test: `tests/test_heavy_product_inspection.py`

**Interfaces:**
- Consumes: `inspect_product(root, profile=None, limits=None)` and `serialize_product_inspection(report, audience)` from `promin.product_inspection`.
- Produces: `promin inspect [--audience client|machine]` and `promin report --inspection INSPECTION.json [--output PATH]`.
- Invariant: report input must be strict canonical JSON with all claims false; output writes are create-only and optional.

- [ ] **Step 1: Write failing command tests**

```python
def test_inspect_cli_is_bounded_static_and_claim_free(tmp_path, capsys):
    (tmp_path / "notes.md").write_text("hello", encoding="utf-8")
    assert main(["--root", str(tmp_path), "--no-telemetry", "inspect", "--audience", "client"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["claims"]["acceptance_pass"] is False
    assert report["effects"]["filesystem_writes"] == 0

def test_report_cli_rejects_promoted_inspection_and_existing_output(tmp_path):
    promoted = {"claims": {"acceptance_pass": True}}
    (tmp_path / "inspection.json").write_text(json.dumps(promoted), encoding="utf-8")
    assert main(["--root", str(tmp_path), "report", "--inspection", "inspection.json"]) == 2
```

- [ ] **Step 2: Run the tests to prove both commands are absent**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_public_workflows_cli.py -k "inspect_cli or report_cli"`

Expected: FAIL because neither public parser command exists.

- [ ] **Step 3: Implement `client_report` as a strict serializer, not a new inspection owner**

```python
def report_from_inspection(report: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(report.get("claims"), Mapping) or any(report["claims"].values()):
        raise ClientReportError("inspection report carries promoted claims")
    return {
        "schema": "promin.client-report.v1",
        "record_type": "ProminClientReport",
        "inspection": json.loads(serialize_product_inspection(report, audience="client")),
        "claims": {key: False for key in report["claims"]},
    }
```

Add parser/dispatch branches that call the existing inspector, accept only
canonical inspection input for `report`, and use a create-only write helper
for explicit `--output`.

- [ ] **Step 4: Run focused inspection/report tests**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_public_workflows_cli.py tests/test_heavy_product_inspection.py`

Expected: PASS; report command cannot convert static inspection into runtime
or release evidence.

### Task 3: Expose clean recovery and revalidation through strict CLI requests

**Files:**
- Modify: `promin/__main__.py:103-115,950-1060,1128-1160`
- Create: `promin/public_recovery.py`
- Test: `tests/test_public_workflows_cli.py`
- Test: `tests/test_alpha4_clean_reinitialization_operation.py`
- Test: `tests/test_revalidation_workflow.py`

**Interfaces:**
- Consumes: `prepare_clean_reinitialization(package_root, project_identity)` and `clean_reinitialize_project(...)` from `promin.clean_reinitialization`.
- Consumes: existing `_run_revalidation(args)` / `execute_revalidation_workflow` behavior.
- Produces: `promin recover clean --request REQUEST.json [--apply]` and `promin revalidate --input INPUT.json [--execute]`.
- Invariant: `recover clean` requires an owner confirmation bound to the exact preparation digest before invoking the real initializer; `revalidate` preserves rejection of recorded PASS.

- [ ] **Step 1: Write failing request and authority tests**

```python
def test_clean_recovery_plan_is_non_mutating_without_apply(tmp_path, package_root, capsys):
    request = make_clean_recovery_request(package_root, tmp_path)
    request_path = write_canonical(tmp_path / "recovery.json", request)
    assert main(["--root", str(tmp_path), "recover", "clean", "--request", str(request_path)]) == 0
    assert not (tmp_path / ".promin-quarantine").exists()

def test_clean_recovery_apply_rejects_wrong_confirmation(tmp_path, package_root):
    request = make_clean_recovery_request(package_root, tmp_path, confirmation_digest="0" * 64)
    assert main(["--root", str(tmp_path), "recover", "clean", "--request", str(write_request(tmp_path, request)), "--apply"]) == 2
```

- [ ] **Step 2: Run to prove the recovery CLI does not exist**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_public_workflows_cli.py -k clean_recovery`

Expected: FAIL with an unsupported `recover` workflow.

- [ ] **Step 3: Implement strict request parsing in `public_recovery`**

```python
def parse_clean_recovery_request(path: Path, *, project_root: Path) -> CleanRecoveryRequest:
    record = load_json_strict(path, root=path.parent)
    require_exact_keys(record, CLEAN_RECOVERY_KEYS)
    return CleanRecoveryRequest.from_record(record, project_root=project_root)

def plan_clean_recovery(request: CleanRecoveryRequest) -> dict[str, object]:
    preparation = prepare_clean_reinitialization(request.package_root, project_identity=request.project_identity)
    return {"record_type": "CleanRecoveryPlan", "preparation": preparation.to_record(), "claims": false_claims()}
```

For `--apply`, adapt the existing `ProminService(...).initialize` call into
the `StandardInitializer` callback required by `clean_reinitialize_project`;
do not reimplement quarantine, publication verification, or rollback.
Add `revalidate` as a thin parser alias to `_run_revalidation`, retaining
`doctor --revalidate` compatibility.

- [ ] **Step 4: Run recovery and revalidation suites**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_public_workflows_cli.py tests/test_alpha4_clean_reinitialization_operation.py tests/test_heavy_revalidation.py tests/test_revalidation_workflow.py`

Expected: PASS; wrong authority, invalid receipt, or callback-promoted PASS
fails before state publication.

### Task 4: Document and integrate the public workflow slice

**Files:**
- Modify: `docs/INIT_CAPABILITIES_UA.md`
- Modify: `docs/REVALIDATION_AND_REPORTING_UA.md`
- Modify: `docs/PRODUCT_INSPECTION_UA.md`
- Modify: `docs/QUICKSTART_IF_THEN_UA.md`
- Modify: `tests/ALPHA4_TEST_SHARDS.json`
- Modify: `MANIFEST.json`, `SHA256SUMS.txt`
- Test: `tests/test_package_validation.py`

- [ ] **Step 1: Update docs with exact commands and no-credit boundary**

Document examples for `init --initial-work prepare`, `inspect`, `recover
clean`, `revalidate`, and `report`; state that tool availability, runtime,
platform, and acceptance are separately evidenced.

- [ ] **Step 2: Add new test modules to the canonical selector shard**

Place public workflow tests in `service-distribution` and recovery tests in
`heavy-hardening` only if their runtime remains within the existing limits.

- [ ] **Step 3: Run all affected test modules and static package checks**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_public_workflows_cli.py tests/test_initial_project_work.py tests/test_alpha4_clean_reinitialization_operation.py tests/test_heavy_revalidation.py tests/test_revalidation_workflow.py tests/test_heavy_product_inspection.py tests/test_package_validation.py`

Run: `python -B tools/promin_validate.py --check --install-mode none`

Expected: PASS with all public-result claims false.

- [ ] **Step 4: Refresh integrity only after all code and docs are stable**

Run the repository-owned package refresh command twice, compare resulting
`MANIFEST.json` and `SHA256SUMS.txt`, then run `git diff --check` and strict
validator verification. The integrator includes this slice, the approved spec,
and subsequent tooling/report slices in one same-version commit.
