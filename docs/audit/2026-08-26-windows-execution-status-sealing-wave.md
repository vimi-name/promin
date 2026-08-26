# Windows execution-status sealing wave

## Scope

This same-version `1.0.0-alpha.4` wave is Windows-only. It resolves the final
r10 sealing contradiction without changing the workload, thresholds,
percentiles, raw predicates, acceptance flags, or existing evidence roots.
No Linux, WSL, Docker, or macOS route was started.

## r10 evidence

The exact r10 run completed all fourteen lifecycle events, 100,000 physical
files, 198,999 physical Relations, 165 bounded semantic-control records, and
600 runtime queries. Recomputed raw evidence had no false contract or
performance predicate:

- query p50/p95/p99: `3.7795 / 22.3018 / 29.6504 ms`;
- commit p95/p99: `238.4177 / 457.6777 ms`;
- semantic ingestion: `107.379323 s`;
- all 73 broad path-query observations were independently marked verified.

Publication correctly rejected the candidate because the producer still
hardcoded `status=fail`, while the independent verifier recomputed the exact
execution status as `pass`. The immutable r10 root remains a terminal
`failure-published` diagnostic with acceptance and pass credit false.

## Change

The producer now derives only the exact harness execution status:

- `pass` when every contract predicate is true and the performance profile is
  wholly within bounds;
- `fail` otherwise;
- malformed or missing boolean predicate surfaces are rejected.

This status does not grant product acceptance, release approval, performance
acceptance, or pass credit. Those fields remain independently false.

## Targeted Windows evidence

- TDD regression failed before the helper existed and passed afterward.
- Full saturation storage/lifecycle suite: `18 passed`.
- Independent source re-review: no P1/P2 findings.

```text
validation_claim=targeted_windows_only
runtime_diagnostic_pass=true
acceptance_pass=false
performance_acceptance=false
pass_credit=false
proxy_acceptance=false
```
