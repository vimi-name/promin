# Promin alpha.4 bounded semantic control wave

## Scope

The exact physical workload remains 100,000 files and 198,999 independently
bound physical link facts.  Neither is materialized as one semantic entity or
one semantic Relation per physical item.  The new control surface holds 100
physical buckets of 1,000 files and caps semantic control state at 256
records/envelopes.  Raw inventory and physical-relation evidence remain
canonical streamed artifacts with candidate, activation, digest, cardinality,
and target bindings.

## Included product paths

- bounded inventory projection and public compact Artifact resolution;
- streaming verified-envelope and physical-evidence validation;
- strict seven-role raw evidence schema and independent audit route;
- deterministic minimal/expert initial-work budgets;
- recovery boundary hardening, language-tool receipt hardening, bounded
  Linux-model contract, and fixed 72-bucket comparison contract.

## Targeted evidence

On Python 3.14 with bytecode and pytest cache writes disabled:

```text
tools/compile_schema.py --check: passed
tools/promin_saturation.py --self-check: passed
305 passed, 13 skipped, 589 subtests passed in 378.06s
```

The test set covered saturation raw artifacts/storage, scale orchestration,
contract mutations, projection, verified envelopes, initial work, comparison,
Linux model, language tooling, and recovery.

## Preserved evidence and claims

The r6, r7, and r11-r31 validation roots/candidates are preserved.  r29
reached terminal FAILED_NO_CREDIT after its physical corpus: its then-current
schema rejected the producer's search.immutable_query_phase.  The corrected
compiler now admits that bounded receipt through an isolated seven-case
schema regression.  r29 and the pre-fix r31 archive are not reused by this
wave.

r33 passed its exact extracted-package validation and generated 100,000
physical files, then failed no-credit when bucket controls requested a public
EventStore refresh after opening a verified commit phase.  The minimal repair
captures the head before entering that phase; a real-service regression
reproduces the old guard error and passes after the correction.  r33 is
preserved and is not reused.

r34 passed the repaired phase boundary, recorded the bounded 137-batch
control state, and reached public retrieval validation.  It failed no-credit
because compact physical inventory output used an undeclared data class.
The compact route now uses the policy-owned untrusted-source class while
retaining path, digest, size, and bucket metadata in its payload; the public
RetrievalPage regression passes.  r34 is preserved and is not reused.

r35 passed exact extracted-package validation, completed its bounded control
state and raw physical evidence publication, then reached release-evidence
schema validation.  It is terminal FAILED_NO_CREDIT: the producer emitted
the verified raw-file ratio and physical-relation predicates while the closed
schema had not yet admitted them.  The root, candidate, extracted package,
and failure receipt remain preserved.  The correction makes the writer,
schema, and evidence recomputation use the same exact 30-predicate set; it
does not grant r35 any credit and r35 is not reused.

r36 passed exact extracted-package validation and the predicate closure, then
reached the next release-evidence schema field.  It is terminal
FAILED_NO_CREDIT because the producer put the local bounded semantic relation
count (`28`) into `core_valid_relations`, whose public physical contract is
exactly `198999`.  The producer now publishes the canonical physical Core
count while retaining the bounded semantic count only in its separate fields.
r36, its candidate, extracted package, raw evidence, and failure receipt are
preserved and are not reused.

Before r37, the independent audit was aligned with the same split: its
top-level validation and its published iteration metrics now use the physical
Core relation count (`198999`), while the explicit bounded semantic relation
fields retain `28`.  This is a preflight correction only; it does not alter
the r36 verdict or grant any credit.

validation_claim=targeted_functional_tier_a
runtime_diagnostic_pass=false
acceptance_pass=false
visual_acceptance=false
performance_acceptance=false
pass_credit=false
g27_g45_pass_credit=false
authority_confirmed=0
authority_pending=8
full_static_scan_deferred=true
proxy_acceptance=false

## Next safe action

Refresh exact integrity, commit this same-version source wave, build one fresh
candidate, and launch exactly one new Windows 100k run from its extraction.
Only a terminal result plus an independent strict audit unlocks aggregates,
modeled Linux, the 72-bucket execution benchmark, inspection, or the client
PDF.
