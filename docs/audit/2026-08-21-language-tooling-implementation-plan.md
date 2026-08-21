# Language Tooling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn selected declarative C/C++, C#, and JVM profile entries into explicit, bounded, evidence-producing local tool actions without automatic installation or acceptance promotion.

**Architecture:** A new `language_tooling` domain module consumes the existing bundled language catalog and owns exact command planning, executable identity probing, allow-listed execution, and immutable receipts. The CLI only selects `plan`, `probe`, or `run`; it does not infer tools, permit arbitrary argv, or become a build system.

**Tech Stack:** Python 3.13, pathlib, subprocess with `shell=False`, existing canonical JSON/digest helpers, pytest temporary fixtures.

**Spec:** `docs/audit/2026-08-21-public-workflow-and-tooling-design.md`

## Global Constraints

- Keep the release version unchanged at `1.0.0-alpha.4`.
- Use only tool IDs already declared by bundled C/C++, C#, and JVM profiles.
- Never install, download, pull, or select a tool implicitly.
- Every executable action uses an explicit argv list, `shell=False`, bounded timeout, no network flag, and a canonical relative working/output path.
- A successful process is diagnostic evidence only: all credit/acceptance/release fields stay false.
- Existing profile composition remains declaration-only until an operator selects a tooling action.

---

### Task 1: Define strict tool action and receipt records

**Files:**
- Create: `promin/language_tooling.py`
- Test: `tests/test_language_tooling.py`

**Interfaces:**
- Produces: `LanguageToolAction`, `LanguageToolPlan`, `LanguageToolReceipt`, and `LanguageToolingError`.
- Consumes: `LanguageCatalog` and `BundledLanguageProfile` from `promin.language_catalog`.
- Invariant: a plan contains `{language_id, capability_id, tool_id, executable, argv, working_directory, output_roots, profile_digest}` and false claims.

- [ ] **Step 1: Write the failing record-validation tests**

```python
def test_plan_rejects_undeclared_tool_and_argv_injection(tmp_path):
    catalog = bundled_catalog_fixture()
    with pytest.raises(LanguageToolingError, match="declared"):
        plan_language_tool(catalog, language_id="c-family", tool_id="powershell", action_id="static-analysis", root=tmp_path)
    with pytest.raises(LanguageToolingError, match="argument"):
        plan_language_tool(catalog, language_id="c-family", tool_id="clang-tidy", action_id="static-analysis", root=tmp_path, arguments=(";", "del"))
```

- [ ] **Step 2: Run the test to verify RED**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_language_tooling.py -k plan_rejects`

Expected: FAIL because no `language_tooling` module exists.

- [ ] **Step 3: Implement immutable records and profile lookup**

```python
@dataclass(frozen=True, slots=True)
class LanguageToolPlan:
    language_id: str
    capability_id: str
    tool_id: str
    executable: str
    argv: tuple[str, ...]
    working_directory: str
    output_roots: tuple[str, ...]
    profile_digest: str

    def to_record(self) -> dict[str, object]: ...

def plan_language_tool(catalog: LanguageCatalog, *, language_id: str, tool_id: str,
                       action_id: str, root: Path, arguments: tuple[str, ...] = ()) -> LanguageToolPlan: ...
```

Map each supported action to a fixed grammar, not a free-form argument list:
`clang-tidy <source> --`, `clang-doc <source>`, `doxygen <config>`, `dotnet
--info`, `docfx <config>`, `javac -version`, `javadoc <source>`, `checkstyle
<config> <source>`, and `spotbugs <target>`.

- [ ] **Step 4: Run all record tests**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_language_tooling.py -k "plan or record"`

Expected: PASS; unrecognized language/tool/action never yields a command.

### Task 2: Probe already-installed tools with executable identity receipts

**Files:**
- Modify: `promin/language_tooling.py`
- Test: `tests/test_language_tooling.py`

**Interfaces:**
- Produces: `probe_language_tool(plan, *, timeout_seconds: int) -> LanguageToolReceipt`.
- Invariant: probe executes only `plan.argv`, captures stdout/stderr bytes/digests, validates executable identity before and after invocation, and sets `status` to `AVAILABLE`, `UNAVAILABLE`, `FAILED`, or `TIMED_OUT` without positive claims.

- [ ] **Step 1: Write failing probe tests with a controlled executable fixture**

```python
def test_probe_receipt_binds_executable_and_stream_digests(fake_tool, tmp_path):
    plan = fake_tool_plan(fake_tool, tmp_path)
    receipt = probe_language_tool(plan, timeout_seconds=5)
    assert receipt.status == "AVAILABLE"
    assert receipt.executable_sha256 == sha256_file(fake_tool)
    assert receipt.stdout_sha256 == sha256_bytes(b"fake-tool 1\n")
    assert receipt.claims == false_claims()

def test_probe_unavailable_has_no_substitute(tmp_path):
    receipt = probe_language_tool(plan_with_missing_executable(tmp_path), timeout_seconds=1)
    assert receipt.status == "UNAVAILABLE"
    assert receipt.invoked is False
```

- [ ] **Step 2: Run tests for RED**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_language_tooling.py -k probe`

Expected: FAIL because probing is unavailable.

- [ ] **Step 3: Implement bounded `subprocess.run` probe**

```python
completed = subprocess.run(
    list(plan.argv), cwd=working_path, shell=False, check=False,
    capture_output=True, timeout=timeout_seconds, text=False,
    env=restricted_environment(),
)
```

Before and after process execution, open only the canonical executable path,
hash the regular file, and reject drift. Restrict captured bytes to a defined
ceiling; classify an exceeded ceiling as failed receipt rather than truncating
silently.

- [ ] **Step 4: Run probe suite**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_language_tooling.py -k probe`

Expected: PASS; timeout, missing executable, nonzero exit, stream ceiling,
and executable drift each emit no-credit receipts.

### Task 3: Execute selected static/documentation actions into declared output roots

**Files:**
- Modify: `promin/language_tooling.py`
- Test: `tests/test_language_tooling.py`

**Interfaces:**
- Produces: `run_language_tool(plan, *, timeout_seconds: int) -> LanguageToolReceipt`.
- Invariant: all output paths are canonical descendants of plan-declared output roots; source outside the root, symlinks/reparse points, shell tokens, network options, and undocumented output locations are rejected before invocation.

- [ ] **Step 1: Write failing output-root and timeout tests**

```python
def test_run_rejects_output_outside_declared_root(fake_tool, tmp_path):
    plan = fake_tool_plan(fake_tool, tmp_path, output_roots=("docs/generated",))
    with pytest.raises(LanguageToolingError, match="output root"):
        run_language_tool(plan_with_output(plan, "../escape"), timeout_seconds=5)

def test_run_receipt_preserves_nonzero_exit_without_credit(fake_tool, tmp_path):
    receipt = run_language_tool(plan_for_nonzero_fake(fake_tool, tmp_path), timeout_seconds=5)
    assert receipt.status == "FAILED"
    assert receipt.exit_code == 9
    assert receipt.claims["acceptance_pass"] is False
```

- [ ] **Step 2: Run tests for RED**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_language_tooling.py -k run`

Expected: FAIL because no execution route exists.

- [ ] **Step 3: Implement output and path guards before subprocess creation**

```python
def _output_path(root: Path, relative: str, allowed: tuple[str, ...]) -> Path:
    candidate = canonical_descendant(root, relative)
    if relative not in allowed:
        raise LanguageToolingError("tool output is outside the declared output roots")
    return candidate
```

Use the same receipt builder as probes; enumerate declared output roots after
completion and bind regular-file relative paths/digests without interpreting
tool output as product success.

- [ ] **Step 4: Run the complete language tooling test file**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_language_tooling.py`

Expected: PASS; tests use fake tools and establish adapter correctness without
claiming host tool availability.

### Task 4: Add a narrow public tooling command and live availability checks

**Files:**
- Modify: `promin/__main__.py:136-180,1256-1293`
- Modify: `docs/LANGUAGE_CAPABILITIES_UA.md`
- Modify: `docs/C_CPP_CAPABILITY_PROFILE_UA.md`
- Test: `tests/test_public_workflows_cli.py`
- Test: `tests/test_alpha4_bundled_language_catalog.py`

- [ ] **Step 1: Write failing CLI tests**

```python
def test_tooling_plan_and_missing_probe_are_claim_free(tmp_path, capsys):
    assert main(["--root", str(tmp_path), "tooling", "plan", "--language", "c-family", "--tool", "clang-tidy", "--action", "static-analysis"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["claims"]["pass_credit"] is False
```

- [ ] **Step 2: Add `tooling {plan,probe,run}` parser and dispatch**

Only `--language`, `--tool`, `--action`, explicit root-relative input/output
values, and bounded `--timeout-seconds` are accepted. Do not expose a general
`--argv` option.

- [ ] **Step 3: Execute real host probes only if tools are present**

Run: `python -B -m promin --root <isolated-root> tooling probe --language c-family --tool clang-tidy --action static-analysis`

Expected: either `AVAILABLE` with executable identity receipt or
`UNAVAILABLE`; neither result is acceptance evidence.

- [ ] **Step 4: Run focused CLI/catalog tests and update package inventory**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_language_tooling.py tests/test_public_workflows_cli.py tests/test_alpha4_bundled_language_catalog.py tests/test_heavy_language_catalog.py`

Update docs and canonical inventory only after the test results are stable.
