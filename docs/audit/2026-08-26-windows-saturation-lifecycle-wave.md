# Windows saturation lifecycle wave

## Scope

This same-version `1.0.0-alpha.4` wave is Windows-only. No Linux, WSL, Docker,
or macOS route was started. It changes the exact 100k saturation harness only
to preserve and classify its own lifecycle evidence; it does not reduce the
required 100000-file or 600-query workload.

## Preserved r40 finding

`D:\ProminValidation\alpha4-r40-100k-20260826T054729956-7c3c917` remains
untouched. Its read-only inspection reports `unclassified`: it has no terminal
result, terminal failure receipt, or lifecycle journal because it predates this
change. That status is intentionally not promoted to a diagnosis, recovery,
pass, performance result, or acceptance claim.

## Standard change

`tools/promin_saturation.py` now writes an fsynced, create-only
`saturation-run-lifecycle.jsonl` for each new run. The fixed order is
physical-generation, inventory, semantic-ingestion, projection,
runtime-queries, result, and evidence-publication. Each record carries false
pass and acceptance fields. A read-only `--inspect-output` route classifies an
existing physical output as result-published, failure-published, incomplete, or
unclassified without resuming, reusing, replacing, or deleting it.

A result is reported as result-published by that inspector only when the
lifecycle journal has closed through evidence publication. The inspector rejects
link/reparse output roots and lifecycle files, so it does not follow a redirected
evidence root. A subsequent saturation invocation still rejects any existing
output directory, preserving prior evidence rather than reusing it.

## Windows Tier-A evidence

- `tests/test_heavy_saturation_storage_budget.py`: `17 passed in 92.74s`.
- `tools/promin_saturation.py --self-check`: Windows diagnostic returned
  `status=pass`, `full_100k_executed=false`, and all acceptance fields false.
- Read-only r40 lifecycle inspection: `status=unclassified`, no pass credit.
- Staged exact-tree `tools/promin_package.py verify-tree .`: `valid=true`.

These are source and targeted Windows diagnostic results only.
`acceptance_pass=false`, `performance_acceptance=false`, and `pass_credit=false`.
No fresh 100k evidence is claimed by this wave.

## Next boundary

After the coherent commit, build one new deterministic Windows candidate and
launch one fresh 100k run from its extracted archive. Do not restart, reuse, or
delete r6, r7, r39, r40, or this wave's integrity staging worktree.
