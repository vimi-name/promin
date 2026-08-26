# Windows content-index linearization wave

## Scope

This same-version `1.0.0-alpha.4` wave is Windows-only. It preserves the
active r8 evidence root and changes the compact physical content-index
integrity path after a live Windows stack sample and SQLite query-plan
inspection found a nonlinear FTS join. No Linux, WSL, Docker, macOS, cleanup,
or additional 100k run was started.

## Finding and change

The active r8 process was observed in
`Projection._inventory_content_index_digest()` through
`ProminService.status()` / `_release_signal`. Its old query drove from
`inventory_records` and left-joined FTS5 by an `UNINDEXED` `id`. The Windows
SQLite plan showed an `inventory_records` scan, an FTS virtual-table scan, and
a temporary ordering tree.

Compact physical rows now retain their already-bounded `search_text` in the
ordinary physical table. The exact content commitment is calculated from that
ordered physical table; FTS alignment is checked in the opposite direction,
once per FTS row through the ordinary-table primary key. The derived index
algorithm is `inventory-content-fts-v2`, so a v1 projection fails closed and
requires a full rebuild from its verified persisted inventory.

The change does not add physical files to semantic entities, semantic rows,
or relations. Physical content search, FTS tamper detection, and orphan
rejection remain required.

## Targeted Windows evidence

- Failing TDD regression before the schema change: `search_text` was absent.
- `python -B -m pytest -p no:cacheprovider -q tests/test_heavy_projection_incremental_shards.py -k compact_content_integrity_uses_indexed_rows_not_fts_nested_scan` -> `1 passed` after the change.
- `python -B -m pytest -p no:cacheprovider -q tests/test_heavy_projection_incremental_shards.py` -> `9 passed`.
- `python -B -m pytest -p no:cacheprovider -q tests/test_events_projection.py -k 'compact_persisted_content_stays_out_of_semantic_storage or projection_status_uses_validated_metadata_counts_without_table_scans'` -> `2 passed`.
- `git diff --check` -> clean.

## Evidence status

The old r8 run remains preserved and active. It is an old-source diagnostic
run, not evidence for this v2 index path. Its lifecycle/result and all
acceptance, performance, and pass-credit claims remain false or pending.

```text
validation_claim=targeted_windows_only
runtime_diagnostic_pass=false
acceptance_pass=false
performance_acceptance=false
pass_credit=false
proxy_acceptance=false
```
