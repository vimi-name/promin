# Promin alpha.3 — Heavy validation wave (R2)

## Active scope

- Branch: `alpha-1.0.0-alpha.3-reconciliation-r2`.
- Scope: Windows path/clone rehydration, provider-receipt mutation guard,
  package-document verification, package inventory, and bounded command-cost
  diagnostics.
- Windows is the current verified deployment scope. Linux and macOS remain
  declared static-only targets without runtime, installability, deployment, or
  acceptance pass credit; this Windows-only evidence scope is non-blocking.
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
- Text payloads are checkout-normalized to LF regardless of `core.autocrlf`,
  while PDF artifacts remain byte payloads. This prevents EOL-only checkout
  drift from invalidating the package checksum tree.
- The Windows provider route binds the installed base CPython interpreter, not
  a lone copied executable. Its receipt fallback re-verifies source identities
  before it may run that interpreter, preserving fail-closed integrity when a
  versioned adjacent Python DLL is required.

## Evidence

| Command / artifact | Result | Notes |
|---|---|---|
| `python tools/promin_alpha_check.py --output ...alpha-check-clone-final.json` | pass | ADG-0 13/13; ADG-090 clone rehydration 49.436 s, bound 90 s. |
| `REC-006` direct gate | pass | `pass_credit=true`; evidence `rec-006-direct-final.json`. |
| `init apply small`, 1 warmup + 3 independent cold samples | pass | p95 28,703.683 ms, budget 30,000 ms; no budget or workload change. |
| final package shard | pass | 54 passed, 147 subtests, 329.10 s. |
| clean staging `verify-tree --install-mode none` | pass | 139-file final inventory is revalidated when the final archive is built. |
| serial `pytest -q -m "not scale"` before final test-only retry patch | fail then targeted repair | 385 passed, 4 skipped, 1 deselected, 774 subtests; the sole failure was a transient Windows executable-sharing race in the receipt-tamper test. The exact repaired test passed 1/1 in 11.67 s. |
| fresh `py -3.14 -m pytest -q -m "not scale"` | blocked / terminated | The complete rerun began, then made no observable completion-stage progress for several minutes after its active child work ended; its owned process tree was terminated. It is neither a pass nor a regression verdict, and does not satisfy the required two-run aggregate gate. |
| `pytest tests/test_service_mutation_cache.py` after F-HV-01 | pass | 2/2. The regression substitutes a byte, preserves file size, and restores `mtime`; the cache guard changes because it includes the file byte digest. |
| `pytest tests/test_bootstrap_mutation_verification.py` after F-HV-01 | pass | 1/1 in 39.80 s on a clean local TMP. This is a targeted verification route, not a new aggregate-suite claim. |
| `py -3.14 -m pytest -q tests/test_concurrency_crash.py` | pass | 17/17 in 35.92 s; independently rerun after the full aggregate became non-conclusive. |
| `py -3.13/-3.14 -m pytest tests/test_alpha3_reconciliation_static.py` | pass | 8/8 on each local Windows interpreter; includes the EOL checkout-policy gate. |
| `py -3.13 -m pytest -m windows_integration tests/test_alpha3_reconciliation_windows.py` | pass | 2/2 in 111.77 s: alias/8.3, deep root, redirected `LOCALAPPDATA`, real non-C: volume, and non-ASCII root. |
| `py -3.14 -m pytest -m windows_integration tests/test_alpha3_reconciliation_windows.py` | pass | 2/2 in 152.71 s after the CPython DLL-neighbourhood repair; same public Windows route. |
| `verify-platform ... --install-mode online-clean` | pass | Exact candidate installation proof on Windows 11 / CPython 3.14.6: clean venv, declared dependency closure, installed console wrapper, and all nine public help routes. The initial failure exposed a verifier defect: the isolated install cwd was incorrectly used to read the source manifest. The repair reads the canonical extracted source root without weakening installed-import isolation. |
| Linux host probe | blocked | WSL distribution cannot attach its missing ext4.vhdx and Docker is unavailable; no Linux runtime claim is made. macOS host is unavailable. |

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

- Two completed fresh full non-scale aggregate runs after the last Windows-race
  repair remain pending. One attempted CPython 3.14 aggregate was terminated
  after a completion-stage hang, so it does not receive pass credit. The
  earlier aggregate failure also remains a failure even though its exact
  repaired test passes.
- Installability is now evidenced only for the exact Windows candidate through
  `verify-platform --install-mode online-clean`; it is not evidence for Linux
  or macOS installation.
- The new byte-integrity cache guard has not received a fresh command benchmark;
  performance acceptance and budget pass credit remain false. The external
  re-audit's 62,163 ms p95 remains an observed host result, not a source claim.
- `OWNER_DECISION_REQUIRED`: the plan has 10.3% serialized headroom but emits
  zero diagnostic source samples for the audited repository. Keep the current
  bounded representation, or define a non-empty source-sampling guarantee
  without consuming the required headroom.
- Linux runtime is `BLOCKED` by the broken local WSL installation and absent
  container runtime. macOS runtime is `PENDING_HOST_EVIDENCE`; both platforms
  are covered only by static declarations and non-normative CI lanes.
- Product, visual, release, and performance acceptance are not claimed by
  this diagnostic/deployable alpha validation wave.
