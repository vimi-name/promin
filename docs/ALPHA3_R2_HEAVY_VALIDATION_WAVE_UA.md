# Promin alpha.3 — Heavy validation wave (R2)

## Active scope

- Branch: `alpha-1.0.0-alpha.3-reconciliation-r2`.
- Scope: Windows path/clone rehydration, provider-receipt mutation guard,
  package-document verification, package inventory, and bounded command-cost
  diagnostics.
- Mrets layer is not present in this repository; UGT scope is not expanded by
  this alpha package.

## Changes made from observed failures

- Containment-root resolution reuses a bounded identity cache, while every
  candidate component remains inspected on each call.
- Clone repair reuses the doctor-resolved plan privately, avoiding a duplicate
  portable-plan resolution without exposing it in public doctor JSON.
- Mutation-context reuse retains post-verification bindings, re-stats every
  bound file and directory, and hashes provider-tree topology on every reuse.
  New, removed, unreadable, raced, or linked receipt entries therefore discard
  the cache and require a full byte verification.
- Activation path metadata and containment checks no longer repeat an
  equivalent symbolic-link lookup after an `lstat`/`stat(...,
  follow_symlinks=False)` already supplied that evidence.
- Candidate archive construction parses PDFs on the authoritative clean
  extraction; successful same-byte PDF summaries are bounded in-process only
  and every call still re-reads, validates, and hashes the PDF bytes.
- The command benchmark cleanup removes only its owned fixture in a bounded
  child process and handles read-only files; cleanup failure remains explicit.
- The receipt-tamper test waits at most five seconds for Windows to release a
  just-executed provider child before writing the intended byte mutation.

## Evidence

| Command / artifact | Result | Notes |
|---|---|---|
| `python tools/promin_alpha_check.py --output ...alpha-check-clone-final.json` | pass | ADG-0 13/13; ADG-090 clone rehydration 49.436 s, bound 90 s. |
| `REC-006` direct gate | pass | `pass_credit=true`; evidence `rec-006-direct-final.json`. |
| `init apply small`, 1 warmup + 3 independent cold samples | pass | p95 28,703.683 ms, budget 30,000 ms; no budget or workload change. |
| final package shard | pass | 54 passed, 147 subtests, 329.10 s. |
| clean staging `verify-tree --install-mode none` | pass | 139-file final inventory is revalidated when the final archive is built. |
| serial `pytest -q -m "not scale"` before final test-only retry patch | fail then targeted repair | 385 passed, 4 skipped, 1 deselected, 774 subtests; the sole failure was a transient Windows executable-sharing race in the receipt-tamper test. The exact repaired test passed 1/1 in 11.67 s. A new full aggregate rerun was deferred; no aggregate-pass claim is made. |

## Claim boundaries

`validation_claim=targeted-heavy-pass-with-full-suite-repair-followup`

`runtime_diagnostic_pass=true`

`acceptance_pass=false`

`visual_acceptance=false`

`performance_acceptance=false`

`pass_credit=false`

`g27_g45_pass_credit=false`

`authority_confirmed=0`

`authority_pending=8`

`full_static_scan_deferred=false`

`mrets_layer=preserved`

`ugt_layer=additive`

`proxy_acceptance=false`

## Deferred

- A fresh full non-scale aggregate run after the last test-only Windows-race
  repair is pending. The earlier aggregate failure must not receive pass
  credit even though its exact repaired test passes.
- Product, visual, release, and performance acceptance are not claimed by
  this diagnostic/deployable alpha validation wave.
