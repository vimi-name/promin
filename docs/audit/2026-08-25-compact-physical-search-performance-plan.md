# Compact Physical Search Performance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox syntax for tracking.

**Goal:** Make compact 100k physical content truthfully searchable and remove the repeated compact-inventory verification scan from each operation in one immutable query phase.

**Architecture:** Compact inventory retains its semantic boundary: physical files remain only in derived physical storage, never `entities`, `entity_fts`, `semantic_rows`, Tasks, or Relations. `inventory_content_fts` is a stream-bound derived physical endpoint index. An immutable query phase captures a full verified projection status once, uses it for phase searches/renewals, and performs a full fresh status/binding comparison at close.

**Tech Stack:** Python 3.14, SQLite FTS5 `unicode61`, canonical JSON/digests, verified inventory stream, pytest.

**Spec:** Owner goal and r38 physical result; [bounded semantic control wave](2026-08-25-alpha4-bounded-semantic-control-wave.md).

## Global Constraints

- Version stays `1.0.0-alpha.4`; no push.
- r35–r38 roots/candidates remain preserved and are never reused/deleted.
- Compact semantic state stays 165 records / 137 envelopes / cap 256; 100k physical rows and 198999 links remain streamed physical evidence.
- The content index creates no semantic Artifact, Task, Relation, `entities`, `entity_fts`, or `semantic_rows` row.
- Exact ID/path outranks content search; FTS input is token-normalized and SQL-parameterized; broad results remain bounded/refinement-only.
- All acceptance, performance, pass-credit, public-release, visual, and G27/G45 claims stay false until fresh physical evidence and audit.
- Executors do not commit, delete, move, package, launch 100k, or spawn subagents; integrator commits one coherent wave after exact integrity refresh.

---

### Task 1: Stream-bound physical content index

**Files:**

- Modify: `promin/projection.py`
- Test: `tests/test_heavy_projection_incremental_shards.py`
- Test: `tests/test_events_projection.py`

**Interfaces:**

- `inventory_content_fts(id UNINDEXED, text)` stores exactly one derived row per compact inventory source row.
- Projection status exposes `inventory_content_index_algorithm`, `inventory_content_index_rows`, and `inventory_content_index_digest`.
- Compact status validation recomputes the physical-content commitment from indexed rows and rejects drift.

- [ ] **Step 1: Write failing compact-index tests**

```python
def test_compact_stream_indexes_content_without_semantic_materialization() -> None:
    projection = rebuild_compact_projection(persisted_inventory_fixture())
    assert projection.search("semantic source", depth=1)["entities"][0]["entity_type"] == "Artifact"
    assert semantic_inventory_counts(projection) == {"entities": 0, "tasks": 0, "relations": 0}

def test_compact_content_index_tamper_fails_status() -> None:
    projection = rebuild_compact_projection(persisted_inventory_fixture())
    tamper_physical_content_index(projection)
    with pytest.raises(ProjectionError, match="content index"):
        projection.status()
```

- [ ] **Step 2: Verify RED**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_heavy_projection_incremental_shards.py -k compact_content`

Expected: compact content query has no Artifact result because physical `search_text` is currently discarded.

- [ ] **Step 3: Implement derived index and commitment**

```sql
CREATE VIRTUAL TABLE inventory_content_fts USING fts5(
  id UNINDEXED,
  text,
  tokenize='unicode61',
  detail='none'
);
```

During compact stream ingestion, insert one `(id, search_text)` FTS row along with one `inventory_records` row. Derive a canonical commitment over rows ordered by `(bucket, path)` with `id`, `path`, `digest`, `size`, and `search_text`; bind it to the verified stream/inventory/manifest digests in projection metadata. Status requires compact FTS row count equal inventory entry count and commitment equality. Noncompact/no-inventory status requires zero physical FTS rows and empty commitment metadata.

- [ ] **Step 4: Verify GREEN**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_heavy_projection_incremental_shards.py tests/test_events_projection.py`

Expected: compact content endpoint is derived only, same-stream rebuild digest is deterministic, and tamper fails closed.

### Task 2: Deterministic physical/semantic candidate union

**Files:**

- Modify: `promin/projection.py`
- Test: `tests/test_search_scale.py`

**Interfaces:**

- Exact `inventory_records.id/path` lookup is tier 0.
- Semantic `entity_fts` and physical `inventory_content_fts` candidates are merged/deduplicated by `(tier, score, id)`.
- A merged result over `top_k` sets `refinement_required=true` and never exposes unselected pages.

- [ ] **Step 1: Write failing query tests**

```python
def test_compact_broad_content_refines_without_unselected_paging() -> None:
    page = compact_projection_search("record", top_k=1)
    assert page["refinement_required"] is True
    assert page["unselected_matches_traversable"] is False

def test_compact_hostile_content_is_parameterized_and_bounded() -> None:
    page = compact_projection_search('hostile " OR *', top_k=1)
    assert page["entities"]
    assert len(page["entities"]) <= 1
```

- [ ] **Step 2: Verify RED**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_search_scale.py -k compact`

Expected: content candidates are absent from compact projections.

- [ ] **Step 3: Implement union**

Normalize user content through existing bounded query-token extraction. Use parameterized FTS MATCH values built from quoted normalized tokens; no raw FTS operators/wildcards are interpolated. Query both FTS tables with `LIMIT top_k + 1`, merge/deduplicate deterministically, preserve exact precedence, and materialize physical candidates through existing `inventory_records` endpoint logic.

- [ ] **Step 4: Verify GREEN**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_search_scale.py`

Expected: broad/content/high-cardinality/hostile classes behave correctly with bounded output and exact path/ID precedence.

### Task 3: Immutable phase status reuse

**Files:**

- Modify: `promin/service.py`
- Modify: `promin/projection.py`
- Test: `tests/test_verified_query_phase.py`

**Interfaces:**

- `ImmutableQueryPhase` retains an immutable validated projection status and a stable binding excluding mutable continuation SQLite bytes.
- Internal phase search/renew routes receive `phase_status`; ordinary public Projection APIs retain fresh status validation.
- `close()` runs `require_current()` and rejects any activation/head/closure/semantic/physical-content/inventory binding drift.

- [ ] **Step 1: Write failing phase tests**

```python
def test_phase_reuses_verified_status_until_close(monkeypatch: pytest.MonkeyPatch) -> None:
    phase = service.begin_immutable_query_phase(max_operations=8)
    phase.search(...)
    phase.search(...)
    assert status_call_count() == 1
    phase.close()
    assert status_call_count() == 2

def test_phase_close_rejects_physical_content_binding_drift() -> None:
    phase = service.begin_immutable_query_phase(max_operations=1)
    mutate_compact_content_commitment()
    with pytest.raises(ProjectionError):
        phase.close()
```

- [ ] **Step 2: Verify RED**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_verified_query_phase.py -k 'reuses_verified_status or physical_content_binding_drift'`

Expected: current phase repeatedly revalidates status and has no physical-content binding.

- [ ] **Step 3: Implement private phase route**

At phase entry keep `projection.require_current(store)`, copy its full validated status, and derive a stable binding over activation/head/implementation/semantic and physical inventory/content commitment fields. Pass this cached status only through private phase `search`/`renew_search` paths. Do not hold a SQLite connection. At close run a fresh `require_current(store)` and compare stable bindings before lease close; phase/lease finally cleanup remains unconditional.

- [ ] **Step 4: Verify GREEN**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_verified_query_phase.py`

Expected: one status scan at entry, zero per phase query, one at close; close rejects tampered physical content; direct public queries stay fresh.

### Task 4: Runtime evidence and package closure

**Files:**

- Modify: `tools/promin_saturation.py`
- Modify: `docs/audit/2026-08-25-alpha4-bounded-semantic-control-wave.md`
- Modify: `tools/promin_validate.py`
- Test: `tests/test_heavy_saturation_storage_budget.py`
- Test: `tests/test_package_validation.py`

- [ ] **Step 1: Write failing runtime fixture assertions**

```python
def test_saturation_compact_content_fixture_has_no_semantic_inventory_rows() -> None:
    result = saturation_compact_content_fixture()
    assert result["physical"]["semantic_proxies"] == 0
    assert result["search"]["content_search_verified"] is True
```

- [ ] **Step 2: Verify RED**

Run: `python -B -m pytest -p no:cacheprovider -q tests/test_heavy_saturation_storage_budget.py -k compact_content`

Expected: current r38 physical result records the content predicates as false.

- [ ] **Step 3: Integrate closure**

Ensure raw query evidence reflects real compact content results and profile calculations remain evidence-only. Record r38 as preserved no-credit evidence and the content/status change without raising claims. Refresh package canonical inventory for any new tracked files; retain strict unexpected-file rejection.

- [ ] **Step 4: Run Tier A and package**

Run focused compact/search/phase/runtime/package suites, compiler check, self-check, and `git diff --check`. Make one coherent same-version commit, build a clean exact candidate, copy only generated integrity changes, prove source/stage equality, and launch exactly one fresh r39 Windows 100k extraction.

## Self-Review

- The physical content index is derived from a verified stream and never enters semantic storage.
- The phase cache avoids repeated status scans but cannot silently outlive a final binding recheck.
- Query tests cover bounded broad/content/hostile/miss behavior before another physical run.
- Task 4 preserves r38 no-credit evidence and gates all downstream acceptance work.

## Execution Handoff

Owner authorized subagent-driven execution. Integrator will run Tasks 1–4 sequentially, review each, make one same-version commit, and never push.
