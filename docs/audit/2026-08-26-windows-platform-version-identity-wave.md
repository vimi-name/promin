# Windows platform-version identity wave

## Scope

This same-version `1.0.0-alpha.4` wave is Windows-only. It resolves an
independent r11 audit finding in platform evidence identity. Existing r11
saturation evidence and all historical roots remain unchanged. No Linux, WSL,
Docker, or macOS route was started.

## r11 evidence and finding

The exact r11 saturation result passed independent raw recomputation with
100,000 physical files, 198,999 physical Relations, 600 runtime queries, all
contract and performance predicates true, and acceptance/pass-credit false.

Independent platform validation rejected the r11 platform receipt because
Python distribution metadata normalized `1.0.0-alpha.4` to `1.0.0a4`, while
the receipt used that normalized value in a field defined as canonical SemVer.

## Change

Platform evidence now keeps three distinct bindings without expanding Core:

- canonical candidate `version` is `1.0.0-alpha.4`;
- installed runtime `runtime_version` is `1.0.0-alpha.4`;
- observed Python metadata normalization is retained in the existing
  `transitive_distributions` record and must equal
  `python_distribution_version()` (`1.0.0a4`).

The validator requires exact distribution shape, one and only one normalized
`promin` metadata row, the exact installed runtime observation, and candidate
SemVer equality. Missing, duplicated, stale, or cross-candidate values fail
closed.

## Targeted Windows evidence

- TDD identity regression: passed after the producer/validator change.
- Focused platform/install tests: `3 passed`, `2 subtests passed`.
- Independent source review: no P1/P2 findings.

## Windows execution findings integrated before the final candidate

The final-candidate preflight found three additional Windows evidence defects.
They are corrected in this same-version wave so the candidate is not rebuilt
and saturated repeatedly after each downstream discovery.

1. `run_selector_shard()` previously returned `UNAVAILABLE` on every Windows
   host because POSIX `RLIMIT_AS` was absent. The runner now executes the exact
   shard with process timeout enforcement and records
   `memory_enforcement=host-responsibility`; no Windows-specific protection
   machinery or memory-enforcement claim was added.
2. The sequential aggregate runner has a measured unchanged-scope lower bound
   of at least `4,082.11` seconds before residual work, so seven `600`-second
   shards under a `3,600`-second aggregate deadline are mathematically
   infeasible. The corrected source closure contains 126 `tests/test_*.py`
   files; the Windows execution manifest covers 125 of 126 and excludes exactly
   `tests/test_heavy_linux_model.py`. That Linux-model file remains in package
   inventory and source digests and is not executed on Windows. The corrected
   manifest uses sixteen deterministic shards in fixed order with the unchanged
   `600`-second / `1,073,741,824`-byte per-shard limits and an exact sequential
   aggregate budget of `9,600` seconds (`16 * 600`). The isolated
   `verified-query` workload is ordered after `service-distribution`, followed
   immediately by its five-case `verified-query-lifecycle` companion shard;
   admission and freshness companion selectors remain in their package and
   service shards. The timeout-hardening partitions are domain-owned:
   `canonical-init`, `eventstore-derived-storage`,
   `alpha4-policy-hardening`, `client-evidence-publication`, and
   `package-integrity`. `package-execution` remains a separate one-selector
   shard. No selector was dropped and no per-shard limit was raised.
3. `promin_saturation_audit.py` still required the obsolete evidence-only
   `status=fail` / `exit_code=1` convention. It now independently validates the
   producer's truthful successful `status=pass` / `exit_code=0` state while all
   acceptance and pass-credit fields remain false.

The new Windows selector aggregate route is sequential, uses the fixed
`not scale` manifest, binds the exact candidate and source closure, applies the
aggregate deadline, stores bounded stdout/stderr plus per-shard receipts, and
independently validates the persisted create-only evidence root. Two final
aggregate runs require two distinct roots; no hidden repeated execution exists.

Focused selector evidence after adversarial fix rounds:

- real subprocess timeout/drain regression: passed;
- focused selector suite: `33 passed`, `1 host-capability skip`;
- aggregate-focused suite: `15 passed`;
- independent final review: spec PASS, code quality approved, no P1/P2.

## Client evidence presentation route

The tools-only client route now independently binds a canonical full product
inspection, external candidate binding, terminal validated Windows saturation
result, and the exact fixed 72-bucket Promin/Markdown/empty comparison. It
derives a path/time/host-safe packet, deterministic invariant PDF, and final
canonical receipt. Publication is create-only; the receipt is published last
and binds all inputs, report bytes, PDF bytes, and ten exact false claims.

Focused client tooling after adversarial fix rounds:

- evidence packet suite: `36 passed`, `1 host-capability skip`;
- complete client-report tool suite: `62 passed`, `2 host-capability skips`;
- direct tools-only `--help`: exit `0` without launcher shadowing;
- independent packet and publication reviews: spec PASS, code quality approved,
  no P1/P2.

The skips concern unavailable local symlink creation only. Static Windows
reparse-point guards and simulated replacement-race coverage passed; the skips
receive no independent PASS credit.

## Live installed-command closure correction

The first fresh same-version r12 Windows platform execution produced a
`status=pass` receipt, but the separate `validate_platform_verification()`
recomputation rejected it with `installed command invocation set is incomplete
or reordered`. The rejected receipt and its extraction root remain preserved;
no 100k run was started from that invalid platform chain.

Root-cause tracing found three divergent alpha.1-era command contours:

- the installer emitted global help plus ten workflow probes;
- both independent evidence validators required only global help plus six
  workflow probes;
- the normative `BASE_USER_COMMANDS` surface contains eleven workflows,
  including `static-admission`.

The producer now probes global help plus all eleven normative workflows in
canonical order. One shared evidence invariant requires those exact twelve
bounded successful rows for both platform and no-degradation evidence, and the
compiled Draft 2020-12 schema requires exactly twelve rows. Missing,
reordered, or extra probes fail closed. Version remains `1.0.0-alpha.4`; no
acceptance or pass-credit field changed.

Fresh correction evidence:

- RED reproduction: two expected failures (missing invariant and omitted
  `static-admission` probe);
- GREEN regression: `2 passed`;
- independent review mutation: strict validator now rejects boolean and
  non-integer zero return codes;
- full package suite: `57 passed`, `307 subtests passed`;
- authority suite: `31 passed`;
- archive/final-package binding: `20 passed`;
- scale orchestration: `42 passed`, `1 host-capability skip`, `22 subtests`;
- installed-distribution tests: `2 passed`;
- exact generated-tree verification: `valid=true`, 295 files, 17 directories.

## Live candidate-binding publication correction

The first r13 selector aggregate preflight rejected the package-generated
candidate binding before any shard started. The package producer wrote stable
sorted but indented JSON, while the public selector CLI correctly required a
byte-canonical machine input. The rejected aggregate root was never created;
the completed r13 100k evidence remains preserved and unchanged.

`promin_package.py build --candidate-binding-output` now publishes the binding
with the shared canonical JSON encoder. The binding object and its digest rules
are unchanged; only its external byte representation is made directly
consumable by strict public workflows. TDD reproduced the pretty/canonical byte
mismatch and the focused package test passed after the correction.

## P2 canonical inventory correction

The confirmed P2 is fixed in the source-owned canonical package and Windows
selector protocol. The obsolete `promin/windows_event_history.py` module and
its two Windows history-seal test selectors are no longer declared by the
canonical inventory or selector manifest. Their portable commit/recovery
coverage is represented by the new
`tests/test_heavy_eventstore_portable_recovery.py` selector in the existing
`heavy-hardening` shard, exactly once. A bounded source-level regression guard
also rejects any renewed runtime dependency on the removed module or class.

The source test closure is now 126 files; Windows executes 125 selectors and
continues to exclude only `tests/test_heavy_linux_model.py`. The manifest now
has sixteen shards in the established order, with the single-selector
`canonical-init`, `eventstore-derived-storage`,
`client-evidence-publication`, and `package-integrity` domains plus the bounded
`alpha4-policy-hardening` partition. Every shard retains `600` seconds and
`1,073,741,824` bytes, and the aggregate budget is exactly `9,600` seconds. The
`tests/test_heavy_eventstore_portable_recovery.py` selector remains in
`heavy-hardening` in bytewise order. All acceptance and pass-credit claims
remain false. The r15 baseline is non-final and remains pending a refreshed
candidate after generated integrity surfaces are rebuilt by the integrator.

The r15 live baseline completed with aggregate `status=TIMEOUT`: ten shards
timed out at the 600-second boundary and only `experience-portability` passed.
Independent process inspection also found concurrent Codex-owned unittest and
harness workloads outside the aggregate process tree. The receipts are
preserved as truthful diagnostic evidence, but the contaminated timing does not
promote acceptance or pass credit. The final candidate must be rerun with zero
concurrent test workloads.

No pytest or physical aggregate was run for this correction while PID 30460
was active. The permitted JSON parse, direct selector loader, AST parse, and
`git diff --check` checks passed; package-list commands remain pending for the
integrator after the live aggregate terminates.

## Remaining exact execution gate

No r12 artifact or downstream result is claimed by this source wave. After the
final integrity refresh and coherent commit, the required order is:

1. build and independently verify one deterministic refreshed same-version
   archive/binding;
2. produce one fresh online-clean Windows platform receipt;
3. launch exactly one fresh 100,000-file / 600-query Windows saturation from
   the refreshed extraction and independently recompute it;
4. run the exact Windows selector aggregate twice in separate evidence roots;
5. execute the fixed 72-bucket comparison;
6. run product inspection and publish the evidence-bound client packet, PDF,
   and receipt.

Linux, WSL, Docker-Linux, and macOS execution remain outside the current owner
scope. No automatic cleanup or deletion is authorized.

```text
validation_claim=targeted_windows_only
runtime_diagnostic_pass=false
acceptance_pass=false
performance_acceptance=false
pass_credit=false
proxy_acceptance=false
```
