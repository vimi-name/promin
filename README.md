# promin

MOROK TOWER

Version 1.0.0-alpha.3

`promin` is a portable operational layer for reliable agent-assisted work. It
turns a goal, backlog, or repository into one visible resolved plan, bounded
Tasks and WorkCards, evidence, self-audit, and the next valid action. Internal
strictness is hidden from the ordinary user but remains inspectable and
configurable.

> **Humans define meaning. Agents clarify and implement.**

`1.0.0-alpha.3` implements general fixes for the Windows/init, portability, detection,
read-only, self-check, and cost defects found by the independent Opus 5 stress review. See
`docs/ALPHA3_OPUS5_FIXES_UA.md` for the exact boundaries and remaining alpha-deferred evidence.

## Installation

Requirements: CPython 3.12, 3.13, or 3.14. Extract the archive to a stable folder; do
not place the Promin virtual environment inside the target repository.

Windows PowerShell:

```powershell
py -3.12 -m venv "$env:USERPROFILE\.venvs\promin"
& "$env:USERPROFILE\.venvs\promin\Scripts\python.exe" -m pip install "C:\path\to\promin"
& "$env:USERPROFILE\.venvs\promin\Scripts\promin.exe" --version
```

macOS or Linux:

```bash
python3.12 -m venv "$HOME/.venvs/promin"
"$HOME/.venvs/promin/bin/python" -m pip install /path/to/promin
"$HOME/.venvs/promin/bin/promin" --version
```

For an offline installation, point pip at an organization-maintained wheelhouse:

```text
python -m pip install --no-index --find-links WHEELHOUSE PATH_TO_PROMIN
```

The installed wheel carries the canonical Core, profiles, prompts, license, and
skill schema under the Python environment; it does not depend on the extracted
source tree after installation.

## Quick start

For the ordinary path:

```text
promin init --goal "Describe the result that matters"
promin init --goal "Describe the result that matters" --yes
promin doctor
promin next
```

Before showing the plan, Promin performs only a bounded metadata preflight. It
detects project mode, workspace units, stack, profiles, language, and reversible
defaults without a questionnaire or hidden full repository scan. Review the
resolved plan, confirm it, or repeat init with a natural-language goal/profile
override. Full expert plans remain available but are not required.

## Canonical owners

The six files in `core/` are the complete Core:

| File | Responsibility |
|---|---|
| `promin.manifest.json` | identity and Core component digests |
| `semantic-model.json` | vocabulary, relations, and provider-neutral capabilities |
| `authority-model.json` | Grants, capabilities, scope, delegation, and separation of duties |
| `policy-set.json` | cross-record invariants and state machines |
| `conformance.json` | acceptance predicates, mutations, and hard budgets |
| `contracts.schema.json` | compiled Draft 2020-12 structural projection |

The schema is generated from the other owners and is not a second semantic or
policy owner. `presets/semantic-morok-tower.json` selects one operating profile
outside Core identity and cannot grant authority.

The selected preset preserves Semantic Programming and Morok/Tower
decomposition as bounded configuration:

| Profile | Model tier | Parallel Tasks | Dependency depth | Context bytes | Entities | Relations | Top-k |
|---|---|---:|---:|---:|---:|---:|---:|
| `morok-local` | `weak-local` | 1 | 2 | 8192 | 16 | 24 | 8 |
| `tower-capable` | `capable` | 3 | 4 | 12288 | 24 | 36 | 10 |
| `tower-strong` | `strong` | 6 | 6 | 16384 | 32 | 48 | 12 |

These profiles alter analysis depth, decomposition, retrieval, and parallelism
budgets only. They do not change capabilities, Grants, acceptance predicates,
or evidence requirements.

## Package contents

The canonical alpha tree contains exactly 139 regular files under 14 declared
directories, including the nested `skills/example` package. `MANIFEST.json`
enumerates all payload files; `SHA256SUMS.txt` closes those payloads together
with the manifest.

| Location | Regular files |
|---|---:|
| package root | 14 |
| `.github/` | 1 |
| `core/` | 6 |
| `docs/` | 15 |
| `examples/` | 1 |
| `human/` | 4 |
| `presets/` | 1 |
| `profiles/` | 13 |
| `promin/` | 31 |
| `prompts/` | 2 |
| `skills/` | 4 |
| `tests/` | 34 |
| `tools/` | 13 |

The 14 root files are exactly `.gitattributes`, `.gitignore`, `CONTRIBUTING.md`, `LICENSE`,
`MACHINE_README.md`, `MANIFEST.json`, `NOTICE`, `pyproject.toml`, `README.md`,
`SECURITY.md`, `SHA256SUMS.txt`, `THIRD_PARTY_NOTICES.md`, `TRADEMARKS.md`, and
`VERSION.json`. License, governance, dependency, and notice closure are part of
the package identity.

Canonical directories are `.github`, `.github/workflows`, `core`, `docs`, `examples`, `human`, `presets`,
`profiles`, `promin`, `prompts`, `skills`, `skills/example`, `tests`, and
`tools`. Missing or additional paths reject. Project evidence, decisions,
operational state, reports, caches, databases, wheelhouses, and secrets stay
outside the distribution tree.

## Commands

The public alpha command surface contains exactly ten commands:

```text
promin init
promin doctor
promin status
promin next
promin validate
promin continue
promin audit
promin refresh
promin context
promin skills
```

`audit`, `refresh`, `context`, and `skills` are operational support commands.
They are non-authoritative: they do not grant capabilities, acceptance, product
credit, or release approval. `refresh` updates hash-bound short documentation,
the local context projection, Git handoff, and native agent-host surfaces.
`context` returns bounded retrieval results. `skills` discovers or manages
license- and digest-bound procedures without turning them into authority.

The ordinary `init` path resolves a plan from repository facts, trusted profile
layers, and safe defaults. The explicit path below preserves complete expert
configuration and accepts an exact standard bundle, selected preset, and five
plan files.

`init` accepts an explicit standard bundle, selected preset, and the five plan
files `project.json`, `standards.json`, `technologies.json`, `licenses.json`, and
`authority.json`. Team-signed trust also requires an explicit JSON array through
`--activation-proofs`; local-owner trust derives its one root proof and rejects
that option. Init verifies the exact inputs, installs the immutable bundle at
`.promin/standard/<digest>/`, and atomically persists exactly these five records:
`project.json` (`ProjectInit`), `standards.json` (`StandardsInit`),
`technologies.json` (`TechnologiesInit`), `authority.json` (`AuthorityInit`), and
`activation.json` (`Activation`). `licenses.json` is a required validation input,
not a sixth installed init record. Every init mode performs zero product scans.

`--emit-plan` validates and canonicalizes the five supplied plan files into a
directory outside `.promin/`; it does not synthesize plans from project IDs or
source paths and rejects `--activation-proofs`. `--review-plan` validates the
supplied inputs without writing project state. `--dry-run` additionally executes
configured provider preflight while remaining non-mutating. Successful provider
observations are digest-bound in a transient in-memory preflight receipt. The
receipt is never an initialization record and is never written under
`.promin/init/`; that directory still contains exactly the five records listed
above. Only plain `init` commits `.promin/` state.
The product repository does not need a root `core/`; only the verified immutable
copy below `.promin/standard/<digest>/` is installed authority.

```text
promin --root PROJECT init --standard-bundle BUNDLE --preset PRESET --project-plan PROJECT_PLAN --standards-plan STANDARDS_PLAN --technologies-plan TECHNOLOGIES_PLAN --licenses-plan LICENSES_PLAN --authority-plan AUTHORITY_PLAN --emit-plan DIRECTORY
promin --root PROJECT init --standard-bundle BUNDLE --preset PRESET --project-plan PROJECT_PLAN --standards-plan STANDARDS_PLAN --technologies-plan TECHNOLOGIES_PLAN --licenses-plan LICENSES_PLAN --authority-plan AUTHORITY_PLAN --review-plan
promin --root PROJECT init --standard-bundle BUNDLE --preset PRESET --project-plan PROJECT_PLAN --standards-plan STANDARDS_PLAN --technologies-plan TECHNOLOGIES_PLAN --licenses-plan LICENSES_PLAN --authority-plan AUTHORITY_PLAN --dry-run
promin --root PROJECT init --standard-bundle BUNDLE --preset PRESET --project-plan PROJECT_PLAN --standards-plan STANDARDS_PLAN --technologies-plan TECHNOLOGIES_PLAN --licenses-plan LICENSES_PLAN --authority-plan AUTHORITY_PLAN
promin --root PROJECT init --standard-bundle BUNDLE --preset PRESET --project-plan PROJECT_PLAN --standards-plan STANDARDS_PLAN --technologies-plan TECHNOLOGIES_PLAN --licenses-plan LICENSES_PLAN --authority-plan AUTHORITY_PLAN --activation-proofs ACTIVATION_PROOFS
```

`doctor` returns one aggregate health report. The report is derived,
non-authoritative, sets `report_authoritative=false` and `pass_credit=false`,
and exposes no token, cost, or usage metrics and no goal, session, batch,
workspace, per-run usage, or per-run allocation. Its health and metrics cannot grant authority,
acceptance, distribution, or public-approval credit.

`status` reads current derived state. `next` requires the subject, a holder
`task.execute` Grant through `--grant`, and a separate `projection.read` Grant
through `--query-grant`. It derives the current bounded `ReadyFrontier` from the
acyclic `DEPENDS_ON` graph, selects the first eligible Task in deterministic
frontier order, and returns its immutable read-only `WorkCard` in
`NextResult.work_card`. A Task is eligible only when every dependency is
currently `COMPLETED`, every required GateResult has current passing credit,
and no current `OPEN` Finding blocks it. `next` is not an FTS query and accepts
no search expression.

`next` and `continue` return strict six-field envelopes with no additional
fields. `NextResult` and `ContinueResult` contain exactly `record_type`,
`status`, `subject_id`, `activation_digest`, `work_card`, and `continuation`, in
that contract order. `status=ready` requires a strict Core `WorkCard`;
`status=empty` requires `work_card=null`. The public `continuation` field is
non-null only when the current `ReadyFrontier` page is truncated, and then
contains only the opaque token for the next frontier page. `continue` requires
that token, the same subject, and a current `projection.read` Grant.
`WorkCardProjection` is internal selected-Task materialization, is not either
public result envelope, and contains no continuation field or token.

```text
promin --root <project> next --subject <id> --grant <holder-grant> --query-grant <query-grant>
promin --root <project> continue <token> --subject <id> --grant <query-grant>
```

## Authority and execution

Authority is default-deny. Bootstrap binds the configured roots, ceilings, and
Activation. A Grant binds its exact signed claim and issuer claim, subject,
capability, conjunctive effect scope, nonce, not-before and expiry times,
revocation state, bounded delegation chain, and signature boundary. Delegation
depth is at most eight. Separation-of-duty rules are evaluated both when a
Grant is issued and when an action is attempted.

A mutation Lease binds one Task, manager and holder Grant claims, generation,
monotonic fence, heartbeat, expiry, and close acknowledgement. Acquire,
heartbeat, expiry, close, and revocation are stateful transitions. `ACTIVE` and
`CLOSING` Leases, together with expired or revoked Leases awaiting recorded
reconciliation, continue to occupy capacity. A Lease authorizes no acceptance,
validation, resolution, waiver, promotion, distribution, or public approval.

Task, Finding, GateResult, and Decision transitions are checked against their
current event-time state. A stale generation, fence, Grant, HEAD, Candidate,
Activation, policy, or implementation binding rejects before mutation.

## Journal and derived state

One normalized command, exact authorization, idempotency key, and expected HEAD
produces one primary event in one bounded atomic EventBatch. Under the single
writer lock, the runtime refreshes HEAD and authoritative state, verifies the
installed bundle bytes, authorizes against that state, and appends durably
before publishing any in-memory or projection change.

EventStorePolicy is rebuilt live from the installed authority and semantic
owners before normalization, mutation, and replay. It has no default or
nullable critical bindings.

Each EventBatch commits the previous authority commitment, cumulative event
count, ordered event semantic digest, a non-empty canonical set/delete delta of
changed typed authority leaves, cumulative state-binding update count, and the
post-batch `typed-sparse-merkle-v1` state-binding root. UTC timestamps have
second precision. Publication uses the local writer lock, file sync, atomic
replace, and directory sync, with explicit crash recovery. Journal replay
verifies the complete prefix; a checkpoint,
SQLite database, typed graph, health result, WorkCard, inventory proxy, or
continuation record is rebuildable and cannot inject authority.

## Evidence, gates, and acceptance

Evidence bytes are immutable CAS Artifacts. Credit resolves an exact Artifact
ID and finalized Artifact-record digest and binds the Candidate, Activation,
policy, tool, provider, inputs, implementation closure, evidence purpose, and
evidence class. `harness-generated` and `product-execution` remain separate.
Failed, blocked, skipped, stale, unresolved, degraded, mixed-class, or
wrong-purpose evidence receives no pass credit.

Every gate is evaluated against an immutable GateRunDefinition precommitted by
its owning Task. The definition fixes the expected evidence class and purpose,
product-credit requirement, exact target kind, digest and scope, and Candidate,
policy, tool, provider, and input digests before a Run or GateResult is submitted. A passing
diagnostic result may remain diagnostic with `pass_credit=false`; it cannot be
promoted into product acceptance. Product acceptance is independent of package,
platform, health, scale, and standard-distribution results.

Pass, fail, and blocked GateResults require exact Artifact bindings. Skipped
requires a reason, carries no Artifact credit, and always has
`pass_credit=false`.

## Inventory

Inventory is an explicit runtime operation, never an implicit part of `init`.
One raw file produces exactly one derived `Artifact` proxy. The runtime owns its
normalized path and content digest and forces the data class to
`untrusted-source`. Inventory does not invent `Task`, `READS`, or `PRODUCES`
facts; those require explicit semantic input.

Inventory writes an immutable canonical JSONL stream while computing rolling
digests, byte count, and entry count. Its manifest binds those values and the
Candidate. Projection rebuild verifies the manifest and consumes the stream in
one pass before atomically publishing the new derived view. It does not need to
materialize the product corpus as an in-memory tuple.

Eligible untrusted text contributes at most 4096 bytes per inventory row to
derived search. Those bytes remain data and can never become a command, policy,
authority claim, or semantic relation.

Only a verified inventory stream may enter public projection rebuild. A
provider-proven `immutable-vcs-tree` may be creditable. An
`observational-best-effort` walk is explicit and non-creditable.

## Projection, retrieval, and continuation

For generic bounded retrieval operations, exact ID resolution precedes FTS.
`RetrievalPage` is the generic retrieval result; it is separate from scheduling
`NextResult` and `ContinueResult` and from internal `WorkCardProjection`. Ranked
lookup selects a bounded top-k seed set. If a broad query has further matches,
the `RetrievalPage` sets
`refinement_required=true` and returns bounded refinement hints; it does not
turn the complete corpus into a pageable result. Typed traversal is performed
only from the selected seeds, and continuation covers their complete selected
closure without duplicate or silent truncation.

Search includes bounded text extracted from eligible untrusted source files as
well as typed record values. Content is data, never a command or authority
claim. Missing content terms return an empty bounded result.

Each Activation has a random local continuation secret under
`.promin/state/secrets/`. Continuation claims are held in a digest-bound local
state record of at most 16 KiB. The caller receives an authenticated opaque
token of at most 256 bytes; continuation metadata may use no more than 10% of a
bounded WorkCard. A `RetrievalPage` owns generic retrieval continuation and uses
only `stream_cursor` and `next_stream_cursor`; the removed cursor aliases are
invalid. Its continuation covers only the complete selected typed closure and
is not ReadyFrontier scheduling continuation.

Separately, `NextResult.continuation` and `ContinueResult.continuation` carry
only ReadyFrontier next-page continuation. That token binds the subject,
current `projection.read` Grant claim, capability and scope, current
ReadyFrontier and deterministic order, cursor, HEAD, projection, budgets, issue
time, expiry, revocation state, and implementation closure. Every resume
rechecks those bindings. `WorkCardProjection` is an internal, non-authoritative
single-Task materialization; it contains no continuation field or token.

## Health and operation metrics

`doctor` is the single aggregate live health command. Its exact current
components are Core, init, providers, recovery, replay, and projection. Each
component and the rollup use only `healthy`, `degraded`, `failed`, or
`incomplete`. Skipping replay makes replay and the rollup incomplete. A missing
or stale projection is reported as incomplete or failed, never healthy.
Configured provider health is based on actual bounded provider observations,
not declared bindings or archival diagnostics.

DoctorResult is live-only, non-authoritative, performs zero product scans, and
always preserves `report_authoritative=false`, `pass_credit=false`,
`product_acceptance_pass=false`, and
`product_public_approval=not_approved`. Its metrics are limited to verified Core
artifacts, verified init records, provider healthchecks executed, event batches,
and current projection entity and relation counts.

OperationMetrics is a separate live-only observation for one command. It may
report only Core-owned duration, changed-record, event-write, projection-update,
runtime-checkpoint, physical-payload-byte, and bytes-per-changed-record fields.
Neither result may invent or allocate token, cost, usage, goal, session, batch,
workspace, per-run usage, or per-run accounting.

## Research draft sanitation

ResearchDraftIntake is bounded transient ingress, not authority. Every source
is bound to an immutable source Artifact receipt, a recomputed content digest,
size and media type, provenance, and an active reviewed or source-verified
license-plan binding. A missing payload may be represented only as
`metadata-only`; every dependent claim then remains blocked, non-authoritative,
and ineligible for normative use.

The bridge distinguishes research questions, hypotheses, assumptions, evidence
claims, and blocked claims, with verification states `unverified`,
`source-bound`, `verified`, and `blocked`. Citation references identify research
sources; evidence references identify independently resolved Artifact records.
They are not interchangeable. Distribution, marketing, and proof claims cannot
become normative facts through this path.

SanitizedResearchDraft contains only source-bound or independently verified
eligible factual candidates. Excluded material remains in a bounded ledger with
its text and digest, source and evidence references, and exclusion reasons. The
result is derived live-only and cannot change GateResult, Decision, acceptance,
pass credit, public approval, or distribution state. Its
`public_release_approved` value remains `false`.

## Import, export, and rebuild

Command, import, replay, rebuild, and export all use bounded canonical parsing,
the compiled Draft 2020-12 schema, and semantic validators. Empty, unknown,
null, stale, degraded, unbound, or cyclic critical inputs reject. Import admits
only supported persistent semantic records; derived health, metrics, frontier,
WorkCard, continuation, inventory, and projection results are rebuilt.

SemanticExport is an export-only record, never a package or authority source.
It binds the exact Candidate, Activation, HEAD, Core, preset, implementation
closure, provider receipt, inputs, and actual output Artifact ID and finalized
record digest. The output digest, size, media type, and semantic-state bytes are
resolved from the exact immutable CAS content and recomputed before export
credit. Exported records are digest-deduplicated and ordered by record digest.
Projection rebuild consumes verified event and inventory inputs, performs zero
product-tree passes, and publishes one disposable view atomically.

## Implementation closure

Activation binds the implementation used to execute the standard: `promin`,
the Python runtime, `jsonschema`, SQLite, cryptographic verification, PDF
verification, and selected adapter components. Evidence and projections bind
the same closure. Component drift invalidates dependent current state; it never
changes immutable historical records.

## Provider protocols

The semantic owner defines exactly nine adapter protocols: control runtime,
shape validation, content identity, local serialization, query projection,
filesystem inventory, export scan, signature, and build dependency. Each
protocol fixes its protocol ID, supported operations, request and response
shape, adapter identity kind, forbidden boundary, and a complete
content-addressed dependency receipt. Unknown operations or bindings reject.

ProviderInvocationEvidence records the exact protocol ID, operation and
operation-contract digest, provider and adapter identities, invocation kind,
dependency-receipt digest, timestamps, exit or outcome, and bounded output
identity actually observed. Full output binds exact `output_digest`,
`output_size_bytes`, and `output_size_ceiling_bytes`. Diagnostic stdout and
stderr captures are separate, bounded to 1 MiB, and carry explicit truncation
flags. A configured provider name, reconstructed command, or raw provider
invocation is not equivalent evidence. Project operations use the installed
receipt-bound dispatch path; provider-specific command lines do not bypass it.

## Migration and cutover boundaries

A one-time importer for existing operational state remains outside the
canonical `promin` tree. It may migrate supported Tasks, Grants, Leases,
evidence, Findings, GateResults, Decisions, revocations, and continuation state
through the same strict ingress. Generated indexes, reports, and databases are
rebuilt rather than migrated as authority.

Cutover requires candidate-bound dual-run parity, deterministic rollback and
recutover, closure of every P0/P1 Finding, zero remaining legacy references,
and an explicit current human Decision. Until those independent conditions are
met, cutover is false and deletion is false. Existing source material remains a
read-only migration reference and is listed only as a deletion candidate; the
standard package neither deletes nor archives it as normative content.

## Exact candidate and decision

Distribution is an acyclic external process:

```text
exact candidate ZIP bytes
-> external StandardReleaseCandidateBinding
-> physically resolved typed evidence
-> external StandardReleaseEvidenceManifest
-> configured signed approve/reject StandardReleaseDecision
-> derived StandardDistributionStatus
```

The CandidateBinding records structural SemVer and the exact archive byte
length and SHA-256 together with package, Core, preset, tool, test, and portable
implementation identities. Exact-package verification and multi-platform
implementation closure are recomputed from that archive and the two platform
records; they are not caller-supplied evidence roles. Evidence manifest entries
name the seven required typed roles, relative paths, record types, predicates,
and SHA-256 values. Verification resolves every referenced regular file below
the explicit evidence root, performs one bounded stable read, hashes and parses
those same bytes, evaluates exact role-specific predicates, and rejects changed,
unresolved, stale, degraded, unknown, or mismatched records.

The decision is outside the ZIP. It contains an explicit `approve` or `reject`
outcome and binds the CandidateBinding and EvidenceManifest digests. It is
accepted only when its `standard.distribute` capability, decider, key, trust
root, validity window, revocation state, nonce, signed claim digest, and Ed25519
signature match the external trust configuration and the SHA-256 of those exact
configuration bytes matches a separately supplied operator pin. A valid
signature under an unpinned caller-supplied root is reported only as
`signature_valid_under_supplied_root`; it cannot approve distribution.

`VERSION.json` describes version and package integrity only. It does not approve
distribution and is never an authority source. Distribution status is derived
as `candidate`, `approved`, `rejected`, or `invalidated` from the verified
external chain.

Build and verify the immutable candidate:

Run the Windows platform command on Windows and the Linux platform command on
Linux; each command observes its current installed environment.

```text
python tools/promin_package.py verify-tree . --install-mode current-environment
python tools/promin_package.py build . ../promin.zip --candidate-binding-output ../evidence/candidate-binding.json --install-mode current-environment
python tools/promin_package.py verify ../promin.zip --candidate-binding ../evidence/candidate-binding.json --install-mode current-environment
python tools/promin_package.py verify-platform ../promin.zip ../evidence/candidate-binding.json ../evidence/windows.json --install-mode online-clean
python tools/promin_package.py verify-platform ../promin.zip ../evidence/candidate-binding.json ../evidence/linux.json --install-mode online-clean
```

Platform/Python matrix records are audit-level compatibility evidence only.
They are non-authoritative, grant no pass credit by themselves, and cannot
authorize distribution or product acceptance. Supplemental interpreter rows do
not add evidence roles to the exact seven-role manifest.

Resolve evidence, create a configured external decision, and verify the full
chain:

```text
python tools/promin_package.py build-evidence-manifest ../promin.zip ../evidence/candidate-binding.json ../evidence ../evidence/evidence-plan.json ../evidence/trust-configuration.json ../evidence/evidence-manifest.json --expected-trust-root-sha256 288fbbb704a905a193088d470f1907c1798098eca903800202396c4a65e89466
python tools/promin_package.py sign-decision ../promin.zip ../evidence/candidate-binding.json ../evidence/evidence-manifest.json ../evidence ../evidence/trust-configuration.json <private-key.pem> ../evidence/decision.json --decision-id <id> --outcome <approve-or-reject> --decider-id <id> --key-id <id> --decided-at <utc-time>
python tools/promin_package.py verify-closure ../promin.zip ../evidence/candidate-binding.json ../evidence/evidence-manifest.json ../evidence ../evidence/decision.json ../evidence/trust-configuration.json --expected-trust-root-sha256 <operator-pinned-sha256> --install-mode current-environment
```

After rendering and reviewing every PDF page, create the candidate-bound PDF
record with `build-document-evidence`; it requires the CandidateBinding, the
external all-pages visual-review record, and exact regular, bold, italic, and
mono font path/digest pairs.

```text
python tools/promin_package.py build-document-evidence . ../promin.zip ../evidence/candidate-binding.json ../evidence/pdf-visual-review.json ../evidence/pdf-pages ../evidence/human-documents.json --font-regular <path> --font-regular-sha256 <sha256> --font-bold <path> --font-bold-sha256 <sha256> --font-italic <path> --font-italic-sha256 <sha256> --font-mono <path> --font-mono-sha256 <sha256>
```

The private key, trust configuration, decision, evidence, and evidence manifest
remain outside the standard ZIP. Building the same canonical tree twice must
produce byte-identical ZIP files.

The evidence manifest resolves exactly seven authority roles, one exact
non-authoritative eight-lane CPython 3.12/3.13/3.14 matrix, and the four CPython 3.14
supplemental records. Every referenced evidence file binds its relative path,
SHA-256, and byte count. Supplemental and nested physical completions are part
of the derived maximum completion time; the matrix cannot grant pass credit.

## Validation lanes

Focused validation excludes the physical scale class explicitly:

```text
python -m pytest -q -m "not scale"
```

Physical scale validation uses the production route and a dedicated workspace.
The scale selection fails when `PROMIN_SCALE_WORKSPACE` is absent; it must never
be converted to a skip.

The physical lane requires exactly 100,000 raw files and derived Artifact
proxies, zero inventory-synthesized Tasks or Relations, and an explicitly
authorized harness corpus that brings the projection to at least 198,999
Core-valid typed Relations. At least 600 actual runtime queries cover exact Artifact and
Task identities, content-only and high-cardinality terms, broad refinement,
misses, hostile identity text, and forced continuation at depths 1 through 12.
Continuation tokens remain at most 256 bytes, persisted state at most 16 KiB,
and unselected broad matches are never traversed.

This bounded physical proof is not a full 1000 by 1000 execution, and it must
not be replaced by one.

Windows PowerShell:

```powershell
$env:PROMIN_SCALE_WORKSPACE = 'C:\promin-scale'
python -m pytest -q -m scale
```

Linux:

```sh
PROMIN_SCALE_WORKSPACE=/tmp/promin-scale python -m pytest -q -m scale
```

No-degradation and saturation evidence bind the exact candidate archive:

```text
python tools/promin_no_degradation.py . ../evidence/no-degradation.json --archive ../promin.zip --install-mode offline-wheelhouse --wheelhouse ../wheelhouse --candidate-binding ../evidence/candidate-binding.json
python tools/promin_saturation.py ../work/physical-100k ../evidence/saturation-run --archive ../promin.zip
python tools/promin_saturation_audit.py . ../evidence/saturation-audit ../work/physical-100k --archive ../promin.zip --physical-evidence-private-key ../evidence/physical-scale.key --physical-evidence-trust-configuration ../evidence/trust-configuration.json --physical-evidence-key-id <physical-key-id> --physical-evidence-producer-id <physical-producer-id>
```

Creditable no-degradation cross-binds the controller platform, CPython version,
ABI and tags to the clean venv executable and SHA-256, the base executable below
its base prefix and its controller-matching SHA-256, and one exact SQLite
version across controller, validation, and installed observations. One monotonic
total deadline covers environment creation, source and wheelhouse copies,
dependency installation, probes, validation, and tests. Every subprocess is
contained as a process tree; descendants are terminated after timeout or parent
exit. Deadline exhaustion, output overflow, orphaned descendants, or missing
progress fails without pass credit.

The saturation outputs above are directories containing
`saturation-result.json` and `saturation-audit.json`. Before the audit command,
configure the process-level `PROMIN_EVIDENCE_*` variables for the distinct
`saturation-audit` producer. The four physical arguments configure only the
nested `physical-scale` producer; the two producers must use distinct keys and
subjects in the same pinned trust configuration.

The saturation audit preserves the incoming `.promin` as a byte-identified
baseline, creates a fresh five-record, zero-scan control state for every full
iteration, never reuses semantic state, preserves each iteration state, and
restores the exact baseline before final publication. The package root, physical
workspace, audit output, active `.promin`, and recoverable operational-state
root are strictly disjoint. Evidence and logs stay in the audit output;
recoverable control state stays below the workspace sibling
`.<workspace>.promin-saturation-audit-state/`. Partial progress has no pass
credit, and `saturation-audit.json` is published only after three consecutive
full zero-new iterations.

The four PDFs in `human/` present the same standard. Their visible cover
identity is limited to MOROK TOWER, `promin`, and the footer `версія 1` or
`version 1`. PDF verification records each document digest, page count,
extraction diagnostics, deterministic rebuild identity, and the explicit scope
of visual review.

Product acceptance remains `false`. Public approval remains `not_approved`.
`public_release_approved` remains `false`. Cutover remains `false`, and deletion
remains `false` until a separately authorized human Decision proves every
cutover precondition.
