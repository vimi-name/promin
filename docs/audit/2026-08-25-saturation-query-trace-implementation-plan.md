# Saturation Query Trace Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox syntax for tracking.

**Goal:** Eliminate the r37 producer/verifier drift by making one bounded, canonical saturation query-page trace the shared source for raw evidence production and release verification.

**Architecture:** `promin/saturation_query_trace.py` owns the 15-field portable trace projection and its validation. The saturation producer serializes only through that module; the release verifier validates the same projection through the same module. A producer-side round-trip check validates every planned raw observation before publication, so a shape drift fails before an expensive release-sealing attempt.

**Tech Stack:** Python 3.14, canonical JSON/digests, JSONL raw evidence, pytest, Draft 2020-12 release schema.

**Spec:** Owner-approved path A in this task; [bounded semantic control wave](2026-08-25-alpha4-bounded-semantic-control-wave.md).

## Global Constraints

- Version remains `1.0.0-alpha.4`; no push.
- r35, r36, and r37 roots/candidates are preserved and never reused or deleted.
- Trace keeps real continuation expiry, renewal, and identity facts; no proxy evidence or pass-credit.
- Semantic control remains 165 records / 137 envelopes / cap 256; physical evidence remains streamed.
- Executors do not commit, delete, move, launch 100k, or spawn agents; integrator makes one coherent same-version commit after exact integrity refresh.
- Python verification uses `-B`, `PYTHONDONTWRITEBYTECODE=1`, and pytest `-p no:cacheprovider`.

---

### Task 1: Domain-owned trace projection

**Files:**

- Create: `promin/saturation_query_trace.py`
- Create: `tests/test_saturation_query_trace.py`

**Interfaces:**

- Consumes an internal page-chain mapping with `atoms`, `page_digests`, `page_identity_digests`, `pages`, `continuation_pages`, `first_truncated`, `initial_expiry`, `expiry_monotonic`, `renewals`, `maximum_token_bytes`, `identity_digests`, and `selected_closure_complete`.
- Produces `build_saturation_query_trace(value: Mapping[str, Any]) -> dict[str, Any]` with exactly 15 portable fields.
- Produces `validate_saturation_query_trace(value: Any) -> dict[str, Any]`, which rejects missing, extra, malformed, non-canonical, or internally inconsistent fields.

- [ ] **Step 1: Write failing tests**

```python
def test_trace_round_trip_preserves_renewal_and_identity_evidence() -> None:
    trace = build_saturation_query_trace(internal_chain_fixture())
    assert validate_saturation_query_trace(trace) == trace
    assert trace["renewal_count"] == 1
    assert trace["page_identity_digests"] == ["a" * 64, "b" * 64]

def test_trace_rejects_legacy_nine_field_projection() -> None:
    with pytest.raises(SaturationQueryTraceError, match="shape"):
        validate_saturation_query_trace(legacy_trace_fixture())
```

- [ ] **Step 2: Verify RED**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_saturation_query_trace.py`

Expected: import or behavior failure because the shared domain module does not yet exist.

- [ ] **Step 3: Implement the minimal domain module**

```python
TRACE_FIELDS = frozenset({
    "pages", "continuation_pages", "first_truncated", "initial_expiry",
    "expiry_monotonic", "renewal_count", "renewal_events",
    "maximum_token_bytes", "selected_closure_complete", "atoms",
    "atoms_count", "atoms_digest", "page_digests",
    "page_identity_digests", "identity_digests",
})

def build_saturation_query_trace(value: Mapping[str, Any]) -> dict[str, Any]:
    ...

def validate_saturation_query_trace(value: Any) -> dict[str, Any]:
    ...
```

The validator must recompute atom count/digest, enforce sorted unique atoms and identities, bind page counts to both digest lists, bind continuation pages to `pages - 1`, require `selected_closure_complete=True`, and validate renewal count/event shape and monotonic expiry facts.

- [ ] **Step 4: Verify GREEN**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_saturation_query_trace.py`

Expected: all new tests pass.

### Task 2: Producer and verifier convergence

**Files:**

- Modify: `tools/promin_saturation.py:4879-4905,5950-5964`
- Modify: `promin/evidence.py:3156-3305`
- Test: `tests/test_heavy_query_tail_scale.py`

**Interfaces:**

- Consumes `build_saturation_query_trace` and `validate_saturation_query_trace` from Task 1.
- Produces raw query observations whose `reference` is exactly a shared 15-field trace and whose forced trace adds only `union_matches_reference`.

- [ ] **Step 1: Write failing integration test**

```python
def test_producer_trace_is_accepted_by_release_query_recomputation() -> None:
    observation = saturation_query_observation_from_real_page_chain()
    recomputed = evidence._recompute_raw_query_result(
        observation, expected_index=0, top_k=1
    )
    assert recomputed["reference"]["renewal_count"] == 1
```

- [ ] **Step 2: Verify RED**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_heavy_query_tail_scale.py -k producer_trace_is_accepted_by_release_query_recomputation`

Expected: the legacy verifier rejects the producer trace shape.

- [ ] **Step 3: Implement convergence and publication guard**

The producer replaces its duplicate `_raw_page_trace` implementation with `build_saturation_query_trace`. Before `_write_jsonl(...query-results.jsonl...)`, validate every `reference` and every non-null forced trace after removal of `union_matches_reference`. The verifier replaces its duplicate exact-key validator with `validate_saturation_query_trace`, preserving forced-union verification and all class-specific page checks.

- [ ] **Step 4: Verify GREEN**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_heavy_query_tail_scale.py`

Expected: producer-derived trace is accepted and malformed renewal/identity traces fail closed.

### Task 3: Release-path regression and wave integration

**Files:**

- Modify: `tests/test_scale_orchestration.py`
- Modify: `docs/audit/2026-08-25-alpha4-bounded-semantic-control-wave.md`
- Regenerate: `MANIFEST.json`, `SHA256SUMS.txt`, and package-derived integrity files only through `tools/promin_package.py`.

**Interfaces:**

- Consumes the shared trace module and producer/verifier behavior from Tasks 1–2.
- Produces an isolated exact 100k/198999 mixed-query raw artifact that reaches release evidence validation without shape mismatch; all acceptance/performance/pass-credit fields remain false.

- [ ] **Step 1: Write failing release-path test**

```python
def test_real_rich_trace_survives_exact_release_recomputation() -> None:
    result = validate_exact_physical_artifact_with_release_verifier()
    assert result["acceptance_pass"] is False
    assert result["pass_credit"] is False
```

- [ ] **Step 2: Verify RED**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_scale_orchestration.py -k real_rich_trace_survives_raw_release_recomputation`

Expected: current divergent page trace is rejected.

- [ ] **Step 3: Integrate and document**

Use the real producer path to emit the rich trace and an isolated 100,000-row inventory plus 198,999-row relation evidence fixture so the real release verifier can recompute it without any downgraded physical scope. Record r37 as preserved terminal no-credit evidence and record the shared-trace correction without changing any acceptance state.

- [ ] **Step 4: Verify GREEN and Tier A**

Run:

```text
python -B tools/compile_schema.py --check
python -B tools/promin_saturation.py --self-check
python -B -m pytest -p no:cacheprovider -q tests/test_saturation_query_trace.py tests/test_heavy_query_tail_scale.py tests/test_scale_orchestration.py tests/test_saturation_raw_artifact_cardinality.py tests/test_heavy_saturation_storage_budget.py
git diff --check
```

Expected: all selected tests pass, and every product/release acceptance field remains false.

### Task 4: Exact package and fresh physical evidence

**Files:**

- Regenerate: package integrity only after Tasks 1–3 pass.

**Interfaces:**

- Consumes a clean same-version source commit and its deterministic archive/binding.
- Produces one new r38 candidate and one fresh direct Windows 100k root.

- [ ] **Step 1: Build clean candidate and compare trees**

Run package build in a fresh clean worktree, copy only generated integrity changes through reviewable patches, and prove every manifest file matches the staging tree before amending the commit.

- [ ] **Step 2: Validate archive extraction before saturation**

Run `python -B tools/promin_validate.py . --install-mode none` only on the fresh extraction and record archive/binding SHA-256, bytes, source HEAD, and all-false claims.

- [ ] **Step 3: Launch exactly one fresh Windows 100k run**

Run `tools/promin_saturation.py` from the r38 extraction with `--files 100000 --queries 600`. Preserve all prior roots and launch a new direct child root only.

- [ ] **Step 4: Gate downstream work**

Only after terminal execution plus independent audit may Windows aggregates x2, modeled Linux, 72-bucket benchmark, product inspection, and client PDF begin.

## Self-Review

- Spec coverage: Tasks 1–3 eliminate the confirmed producer/verifier drift and add an early boundary guard; Task 4 preserves exact-package and physical-proof requirements.
- Placeholder scan: no placeholder implementation steps; trace fields, commands, and expected outcomes are explicit.
- Type consistency: Task 1 owns both trace functions; Task 2 imports them; Task 3 calls the real producer/verifier path; Task 4 contains no new trace interface.

## Execution Handoff

The owner already authorized subagent-driven execution. Integrator will run Tasks 1–4 sequentially with strict file ownership, task-scoped review, one coherent same-version commit, and no push.
