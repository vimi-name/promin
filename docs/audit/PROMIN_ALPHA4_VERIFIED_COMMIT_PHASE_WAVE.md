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
- r18 Windows 100k remains an older, still-running physical attempt and has no terminal result. It receives no pass credit and is not evidence for this wave.

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

Refresh deterministic package integrity, make one coherent same-version commit, then terminate the superseded r18 attempt only through its launcher so it leaves a preserved terminal receipt. Build a fresh deterministic candidate from the committed source and run the next exact Windows 100k workload from that extraction only.

## R19 observation and follow-up binding wave

The fresh r19 candidate reached the exact physical corpus sequence of 1604 commits, then spent an extended period revalidating every durable envelope during corpus inspection. The run was deliberately stopped after this bottleneck was directly observed. Its preserved launcher terminal is `LAUNCHER_REJECTED_NO_PASS_CREDIT` with exit code `-1`; independent audit found no raw saturation artifact chain, so neither the physical corpus nor its performance receives credit.

The follow-up source change makes the verified commit phase retain an exact phase-owned activation and implementation binding. Each phase operation now rechecks that binding before it can use cached mutation context, and close clears the phase mutation cache before a public commit resumes. Static review approved the fail-closed lifecycle. Collection of the five real-fixture tests succeeds; their execution remains `PENDING_FUNCTIONAL_TIER_A` because provider identity initialization did not reach assertions within the bounded run.
