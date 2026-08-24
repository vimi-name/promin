# Promin alpha.4 verified commit phase wave

## Active scope

This same-version wave adds a bounded verified commit phase for the exact saturation path. Public commits retain their normal fresh verification. The phase performs full verification at admission and close, keeps a bounded durable binding between operations, and fails closed on poison, authority drift, or tail drift. The derived checkpoint remains recoverable rather than authoritative.

The saturation route now calculates its exact number of physical relation commits and uses the service-level phase without changing the required workload shape.

## Targeted evidence

- `py -3.13 -B -m pytest -q tests/test_verified_commit_phase.py tests/test_verified_commit_phase_refresh_budget.py tests/test_verified_commit_phase_tamper.py tests/test_init_layer_configured_routes.py`
  - `25 passed in 59.44s`
- Independent scoped re-review: no residual P1/P2 in the EventStore fail-closed fix.
- `py_compile` for changed production files and focused tests: passed.
- `git diff --check`: passed before integrity refresh.

## Deferred evidence

- `tests/test_verified_commit_phase_service.py`: three real lifecycle cases passed. The remaining poison-close-to-ordinary-service-commit case reaches the real phase route, but a subsequent run was externally interrupted during initialization after the assertion was corrected. `PENDING_FUNCTIONAL_TIER_A`.
- The restored physical-relation saturation test is a real service route but its current cold fixture materializes provider receipts before phase execution. A compact real service-route regression remains `PENDING_SATURATION_REAL_ROUTE`; no recorder/mock result is counted as evidence.
- r18 Windows 100k was an older physical attempt without a terminal result. Its exact stale process tree was stopped after identity verification; the root is preserved, receives no pass credit, and is not evidence for this wave.

## Claims

validation_claim=targeted_partial
runtime_diagnostic_pass=false
acceptance_pass=false
visual_acceptance=false
performance_acceptance=false
pass_credit=false
g27_g45_pass_credit=false
authority_confirmed=0
authority_pending=8
full_static_scan_deferred=true
mrets_layer=preserved
ugt_layer=additive
proxy_acceptance=false

## Next safe action

This historic next action is superseded by the r20 interruption and deterministic VCS-boundary follow-up below.

## R19 observation and follow-up binding wave

The fresh r19 candidate reached the exact physical corpus sequence of 1604 commits, then spent an extended period revalidating every durable envelope during corpus inspection. The run was deliberately stopped after this bottleneck was directly observed. Its preserved launcher terminal is `LAUNCHER_REJECTED_NO_PASS_CREDIT` with exit code `-1`; independent audit found no raw saturation artifact chain, so neither the physical corpus nor its performance receives credit.

The follow-up source change makes the verified commit phase retain an exact phase-owned activation and implementation binding. Each phase operation now rechecks that binding before it can use cached mutation context, and close clears the phase mutation cache before a public commit resumes. Static review approved the fail-closed lifecycle. Collection of the five real-fixture tests succeeds; their execution remains `PENDING_FUNCTIONAL_TIER_A` because provider identity initialization did not reach assertions within the bounded run.

The real binding suite subsequently reached its assertions: the initial run had five passing cases and one fixture-only failure caused by selecting protected `C:\\Python313\\DLLs\\_sqlite3.pyd` for physical drift. The test now changes and restores metadata only on a bound file inside the temporary project root; its rerun passed (`1 passed in 176.70s`). The complete suite was not rerun after that fixture-only correction, so complete-suite runtime evidence remains pending.

## Verified envelope snapshot wave

The r19 rejection exposed a post-corpus inspection bottleneck: the saturation inspector replayed schema validation for every envelope that had already been validated at commit time and bound by the authority chain. The follow-up creates an opaque `VerifiedEnvelopeSnapshot` only after strict admission validates the full journal, semantic rows, head/counts, and exact control/journal bytes. The snapshot yields the exact bound canonical records once; it checks state before every emission and fails closed on close, reuse, reopen, byte, head, authority, or foreign-writer drift. Public envelope iteration is unchanged and retains validation.

Saturation prefers the snapshot only when that real API is available; otherwise it explicitly keeps the public `iter_envelopes(validate=True)` route. Focused evidence: snapshot `9/9`, consumer `3/3`; independent review found no residual P1/P2. This is a diagnostic performance-path correction only: `acceptance_pass=false`, `performance_acceptance=false`, and a fresh physical candidate is still required.

## R20 interruption and deterministic VCS boundary

Three r20 roots were created while the host still had an older r18 workload. Two r20 children were exact duplicate launches and were stopped after their Python and launcher command lines were matched; their roots remain preserved and receive no credit. The single intended r20 root generated all 100,000 physical files, then stopped progressing before any semantic event batch or terminal artifact. Read-only process tracing identified the blocking boundary as `git commit` spawning `git maintenance run --auto --quiet --detach`; the process tree was stopped after that fact was captured. The canonical r20 root is therefore preserved as `interrupted/no-credit`, not as a successful terminal run.

The next source wave makes the VCS snapshot pass `-c maintenance.auto=false` explicitly to both the real `git add` and `git commit` operations. It still stages and commits the complete product tree; the returned descriptor records the policy and operations. A narrow test first failed because the configuration pair was absent, then passed after the production change (`1 passed in 41.15s`). This does not prove a new physical 100k run or a performance result; that evidence is pending a new committed deterministic candidate.

## Canonical init product inspection

The main product command already exposes `promin init` with deterministic `minimal` as its default `--init-experience`, explicit `expert` selection, bounded `--max-preflight-files`, and advanced goal, autonomy, language, profile, brief, capability-selection, plan, bundle, review, and dry-run options. The temporary duplicate simple-init API/CLI surface was removed rather than retained as parallel authority. This inspection proves command discovery and option wiring only; provider-backed apply/runtime evidence remains pending.

## Updated claims

validation_claim=targeted_partial
runtime_diagnostic_pass=false
acceptance_pass=false
visual_acceptance=false
performance_acceptance=false
pass_credit=false
g27_g45_pass_credit=false
authority_confirmed=0
authority_pending=8
full_static_scan_deferred=true
mrets_layer=preserved
ugt_layer=additive
proxy_acceptance=false

## Next safe action

Run the focused canonical-init and VCS-policy tests together, refresh exact package integrity, commit the minimal same-version source wave, then build one fresh candidate. Launch exactly one fresh Windows 100k workload from that extraction; only a terminal result plus the independent strict auditor can unlock aggregates or modeled Linux/WSL.

## Cheap saturation-init repair wave

The first r22 root was rejected before corpus creation because its manual launcher pre-created the saturation output directory. The second r22 root passed that precondition but was deliberately interrupted after more than 625 seconds without `.promin`, semantic rows, or a child provider process. Both roots are preserved and receive no credit.

Stack probes then isolated five distinct cold-init costs: repeated Draft 2020-12 schema meta-validation, thread startup in the complete jsonschema receipt, per-file provider-directory syncs, a non-relocatable copied Python payload used for `--version`, and a second full scan of receipts already verified in the same preflight transaction. The repair keeps full Core validation for public/default routes, full provider dependency bytes/digests, final per-directory durability, and persisted/recovery receipt verification. It makes only the exact package-admitted saturation route opt into already-admitted schema metadata, hashes the same jsonschema file set serially, batches directory durability after all component copies, runs an independently digest-verified host Python interpreter for receipt-backed runtime healthchecks, and reuses the preflight's completed receipt verification for the transient identity.

Focused evidence: `tests/test_saturation_schema_meta_policy.py` plus three relevant canonical init/provider tests passed `8/8` in `14.75s`. A fresh clean saturation-init diagnostic returned `status=created` in approximately 18 seconds. This is init-stage diagnostic evidence only; no physical 100k, acceptance, performance, or pass credit is granted. A new deterministic candidate is required before any new physical workload.

## R23 empty-snapshot correction

The fresh r23 candidate passed its repaired init, generated all 100 physical buckets, completed the full Git add and commit with `maintenance.auto=false`, and completed immutable Git archive inspection. It then failed before semantic corpus creation because the verified-envelope snapshot assumed that `HEAD.json` already existed. A fresh EventStore has a canonical journal authority root and checkpoint but no journal head until its first commit.

The snapshot now binds that canonical empty authority root with an explicit absent-head marker, rejects partial/contradictory empty state, and still detects the creation of the first head as durable drift. The regression proves an empty snapshot yields no envelopes and a following first commit succeeds. Full verified-envelope snapshot plus saturation-init-policy tests passed `15/15` in `116.95s`. r23 remains preserved failed/no-credit evidence; a new deterministic candidate is required for the next exact 100k run.

## R24 semantic commit-phase correction

The fresh r24 candidate completed initialization, all 100 physical buckets, full Git add and commit with automatic maintenance disabled, and immutable Git archive. Live stack evidence then showed the first semantic corpus mutation calling the public `runtime.commit` route, which rehashed the activation byte surface before every batch. The root was stopped after this exact boundary was observed and is preserved as interrupted/no-credit evidence.

The bootstrap grants, Candidate record, and bounded search tasks now use one verified service commit phase sized exactly to `5 + len(specs)`. Each command still uses the full service validation/evidence route; only repeated EventStore admission is reused under the finite phase binding. Focused saturation-policy, verified commit phase, and verified envelope snapshot suites passed `27/27` in `178.77s`. No new physical result, acceptance, performance result, or pass credit is claimed until a fresh candidate completes its 100k run and independent audit.

## R25 cold provider-healthcheck correction

The r25 exact candidate was bound to source `a66db7e`, archive SHA-256 `b7b1075335175019ff1f3f08d96632a2a3087db58ab39f65aabdc5ce5dc65874`, and a fresh direct child under `D:\ProminValidation`. The first launcher-created r25 root failed before a saturation workspace or output existed and remains preserved/no-credit. The succeeding fresh r25 root passed extracted-package validation and storage preflight, then rejected before physical corpus creation: its `SaturationFailure` records `python-control-runtime` timing out on the real bound `C:\Python313\python.exe --version` after the declared five-second limit. It has no completed result, no product corpus, and no authority evidence.

The next same-version correction preserves the real executable healthchecks and their fail-closed behavior. It gives the Python and Git saturation provider bindings one explicit 30-second cold-start budget rather than a five-second limit that this Windows host demonstrably exceeded. The bound executable, argv, expected exit, dependency receipts, and output limits remain unchanged. The new focused policy regression and the complete saturation schema-meta policy file passed (`7 passed in 20.68s`). This is source/test evidence only: the r25 roots remain failed/no-credit and a newly bound candidate plus a fresh exact Windows 100k run are still required.

## Updated claims

validation_claim=targeted_partial
runtime_diagnostic_pass=false
acceptance_pass=false
visual_acceptance=false
performance_acceptance=false
pass_credit=false
g27_g45_pass_credit=false
authority_confirmed=0
authority_pending=8
full_static_scan_deferred=true
mrets_layer=preserved
ugt_layer=additive
proxy_acceptance=false

## Next safe action

Refresh exact package integrity, commit this bounded same-version provider-healthcheck policy wave, build one fresh candidate, and launch exactly one new isolated Windows 100k run from its extraction. Do not run aggregates, modeled Linux/WSL, the 72-bucket benchmark, product inspection, client PDF, or cleanup until that run is terminal and independently audited.

## R26 archive-binding document-revalidation correction

The Python 3.14 r26 route removed the host Python 3.13 timeout boundary, completed launcher extraction validation, and reached saturation archive binding. It then spent more than twelve minutes in a second `pypdf` text extraction of the same packaged human documents before creating the saturation workspace. The package build and the launcher had already performed their full document checks; the saturation binder was also independently checking ZIP CRC, canonical entries, every member byte against the folder, manifest/checksum closure, and a deterministic archive rebuild. The interrupted root is preserved with an operator interruption record and has no corpus, result, authority, acceptance, or performance credit.

`verify_archive` now has an explicit `require_docs` switch that defaults to `true` for package build, public/archive verification, and launcher validation. Only `build_artifact_binding` sets it to `false`, after its local member-byte closure, so it avoids repeating PDF text parsing while retaining all archive and candidate-binding checks. The saturation-policy file passed `8/8` after the regression was added. This remains a targeted source correction only; a new exact archive and a fresh Windows 100k run are required.

## Updated claims

validation_claim=targeted_partial
runtime_diagnostic_pass=false
acceptance_pass=false
visual_acceptance=false
performance_acceptance=false
pass_credit=false
g27_g45_pass_credit=false
authority_confirmed=0
authority_pending=8
full_static_scan_deferred=true
mrets_layer=preserved
ugt_layer=additive
proxy_acceptance=false

## Next safe action

Refresh exact package integrity, commit this same-version archive-binding correction, build a new candidate, and run exactly one fresh Windows 100k workload with Python 3.14. Only a terminal result and an independent strict audit can unlock downstream aggregates, modeled Linux/WSL, comparative benchmark, inspection, or client material.
