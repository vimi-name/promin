# Windows broad-search and dependency-batch wave

## Scope

This same-version `1.0.0-alpha.4` wave is Windows-only. It responds to two
terminal r9 findings without changing the saturation workload, percentile
calculation, profile thresholds, atomic event batches, or acceptance flags.
No Linux, WSL, Docker, or macOS route was started.

## r9 findings

The exact r9 run completed 100,000 physical files and 600 runtime queries, but
published `status=fail` because:

- broad query `record` existed in physical paths but not in the content-only
  compact FTS index, so all 73 broad observations were empty;
- the 17-record fanout commit measured `1084.9877 ms`, above the `1000 ms`
  commit-p99 ceiling.

The r9 result remains preserved with all acceptance and pass-credit claims
false.

## Changes

The compact physical index now binds bounded path text together with bounded
content text. Its algorithm identity is `inventory-content-fts-v3`; v1 and v2
metadata fail closed and require a verified rebuild. Broad path queries now
return a deterministic physical Artifact plus bounded refinement while
unselected matches remain non-traversable.

Dependency batches now bind immutable task/relation/gate/finding tuples and
run the complete dependency graph validation once per atomic batch. Every
Relation still traverses schema, domain/range, activation, identity, and
effect-scope validation. Event ordering, receipts, state binding, recovery,
and the 17-record atomic batch are unchanged.

## Targeted Windows evidence

- Broad-path TDD regression: failed with zero entities before the change;
  passed after the change.
- Dependency-batch TDD regression: observed 28 graph validations before the
  change and exactly 13 dependency-bearing batch validations afterward.
- Focused permanent corpus measurement retained at
  `C:\Temp\promin-r10-commit-measure-20260826T202200`: fanout commit
  `383.9327 ms` versus r9 `1084.9877 ms`.
- Compact projection suite: `11 passed`.
- Full relation-ledger suite: `9 passed`.
- Independent source review: no P1/P2 findings.

## Evidence status

The focused measurements prove the corrected routes, not release readiness.
A fresh exact Windows 100k run and independent evidence audit remain required.

```text
validation_claim=targeted_windows_only
runtime_diagnostic_pass=true
acceptance_pass=false
performance_acceptance=false
pass_credit=false
proxy_acceptance=false
```
