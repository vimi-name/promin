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
- Mutation-context reuse retains post-verification bindings, re-reads their
  cryptographic byte digest, re-stats every bound file and directory, and hashes
  provider-tree topology on every reuse. New, removed, unreadable, raced,
  linked, or same-size/timestamp-restored byte-modified receipt entries therefore
  discard the cache and require a full byte verification.
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
| `pytest tests/test_service_mutation_cache.py` after F-HV-01 | pass | 2/2. The regression substitutes a byte, preserves file size, and restores `mtime`; the cache guard changes because it includes the file byte digest. |
| `pytest tests/test_bootstrap_mutation_verification.py` after F-HV-01 | pass | 1/1 in 39.80 s on a clean local TMP. This is a targeted verification route, not a new aggregate-suite claim. |

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
- The new byte-integrity cache guard has not received a fresh command benchmark;
  performance acceptance and budget pass credit remain false. The external
  re-audit's 62,163 ms p95 remains an observed host result, not a source claim.
- `OWNER_DECISION_REQUIRED`: the plan has 10.3% serialized headroom but emits
  zero diagnostic source samples for the audited repository. Keep the current
  bounded representation, or define a non-empty source-sampling guarantee
  without consuming the required headroom.
- Product, visual, release, and performance acceptance are not claimed by
  this diagnostic/deployable alpha validation wave.
