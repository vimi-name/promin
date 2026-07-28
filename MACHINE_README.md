# promin machine entrypoint

Canonical name: `promin`

Standard version: `1.0.0-alpha.3`

## Installed runtime bootstrap

The supported alpha installation path is a dedicated CPython 3.12/3.13/3.14 virtual
environment. Build/install from the extracted canonical folder with
`python -m pip install PATH_TO_PROMIN`, then verify `promin --version`. The wheel
installs the runtime package plus the canonical runtime bundle below
`<venv>/share/promin`; installed execution MUST NOT depend on the source fixture
or current working directory. Offline installations use an explicit hash-bound
wheelhouse through `--no-index --find-links`.

After installation, initialize a target repository with a review-first pass:

```text
promin --root PROJECT init --goal "Describe the result that matters"
promin --root PROJECT init --goal "Describe the result that matters" --yes
promin --root PROJECT doctor --checklist
```

## Authority and identity

Use this order:

1. Verify `MANIFEST.json` and `SHA256SUMS.txt` as the closed tree identity.
2. Read `VERSION.json` only as a descriptive version and integrity pointer.
3. Verify exactly six Core files and every digest in
   `core/promin.manifest.json`.
4. Load semantic, authority, policy, and conformance owners.
5. Treat `core/contracts.schema.json` as their deterministic Draft 2020-12
   structural projection, never as a second owner.
6. Verify the one selected preset outside Core identity.
7. Reject aliases, unsafe paths, normalization collisions, symlinks, special
   files, caches, databases, secrets, and unmanifested payloads.

`VERSION.json` MUST NOT contain or imply an approval decision. The structural
SemVer owner for an exact archive is its external
`StandardReleaseCandidateBinding`. Distribution state is always derived from
the external verified chain.

## Exact package inventory

The canonical alpha tree contains exactly 121 regular files under 14 declared
directories, including the nested `skills/example` directory:

| Location | Regular files |
|---|---:|
| package root | 13 |
| `.github/` | 1 |
| `core/` | 6 |
| `docs/` | 12 |
| `examples/` | 1 |
| `human/` | 4 |
| `presets/` | 1 |
| `profiles/` | 13 |
| `promin/` | 31 |
| `prompts/` | 2 |
| `skills/` | 4 |
| `tests/` | 21 |
| `tools/` | 12 |

Root files are exactly `.gitignore`, `CONTRIBUTING.md`, `LICENSE`,
`MACHINE_README.md`, `MANIFEST.json`, `NOTICE`, `pyproject.toml`, `README.md`,
`SECURITY.md`, `SHA256SUMS.txt`, `THIRD_PARTY_NOTICES.md`, `TRADEMARKS.md`, and
`VERSION.json`. License, governance, dependency, and notice closure is part of
package identity.

`MANIFEST.json` enumerates all canonical files except its own generated digest
closure; `SHA256SUMS.txt` binds every payload plus the manifest. Missing,
additional, linked, special, or transient paths reject.

## Selected preset

`presets/semantic-morok-tower.json` is outside Core identity. It selects bounded
Semantic Programming, Morok/Tower decomposition, retrieval, and parallelism
budgets only:

| Profile | Tier | Parallel | Depth | Context bytes | Entities | Relations | Top-k |
|---|---|---:|---:|---:|---:|---:|---:|
| `morok-local` | `weak-local` | 1 | 2 | 8192 | 16 | 24 | 8 |
| `tower-capable` | `capable` | 3 | 4 | 12288 | 24 | 36 | 10 |
| `tower-strong` | `strong` | 6 | 6 | 16384 | 32 | 48 | 12 |

The preset cannot grant authority or relax acceptance, evidence, provider, or
ingress rules.

## Public command surface

The public alpha surface is exactly:

```json
["init", "doctor", "status", "next", "validate", "continue", "audit", "refresh", "context", "skills"]
```

The last four commands are non-authoritative operational support. They may
observe, rebuild derived surfaces, return bounded context, or manage
license/digest-bound skills, but cannot create action authority or pass credit.
No hidden optional or administrative command list extends this surface.

`next` uses two independently verified Grants:

```text
--grant        holder Grant with task.execute
--query-grant  query Grant with projection.read
```

`next` accepts no FTS query. It derives a bounded `ReadyFrontier` from current
Task, `DEPENDS_ON`, GateResult, and Finding state, selects its first item in
deterministic frontier order, and returns `NextResult.work_card` as an immutable
read-only `WorkCard`. `continue` requires
`TOKEN --subject SUBJECT --grant QUERY_GRANT`; that Grant is the current
`projection.read` query Grant.

`NextResult` and `ContinueResult` each have exactly six fields and no others:

```text
record_type status subject_id activation_digest work_card continuation
```

The fields occur in that contract order. `status=ready` requires `work_card` to
be a strict Core `WorkCard`; `status=empty` requires `work_card=null`.
`continuation` is non-null only when the current ReadyFrontier page is truncated
and then carries only the opaque token for the next frontier page.
`WorkCardProjection` is internal selected-Task materialization, is not a public
result envelope, and contains no continuation field or token.

```text
promin --root PROJECT doctor
promin --root PROJECT status
promin --root PROJECT next --subject SUBJECT --grant HOLDER_GRANT --query-grant QUERY_GRANT --depth 2
promin --root PROJECT validate
promin --root PROJECT continue TOKEN --subject SUBJECT --grant QUERY_GRANT
promin --root PROJECT audit --plan
promin --root PROJECT refresh
promin --root PROJECT context "repository architecture" --limit 12 --max-bytes 8192
promin --root PROJECT skills list
```

## Initialization

The initialization request explicitly supplies:

```text
standard bundle
selected preset
project plan
standards plan
technologies plan
licenses plan
authority plan
```

The five plan files are exactly `project.json`, `standards.json`,
`technologies.json`, `licenses.json`, and `authority.json`. For `team-signed`
trust, `--activation-proofs ACTIVATION_PROOFS` additionally names an explicit
JSON array of signature proofs. `local-owner` derives its one local root proof
and rejects that option. `--emit-plan` also rejects it because plan emission
does not emit Activation proofs.

Before mutation, verify all digests, required providers, Core and preset
identities, implementation closure, and configured authority boundary. Install
the immutable standard under `.promin/standard/<digest>/` and atomically create
exactly five initialization records. Initialization performs zero product-tree
passes.

Initialization preparation is also explicit and non-mutating:

```text
promin --root PROJECT init --standard-bundle BUNDLE --preset PRESET --project-plan PROJECT_PLAN --standards-plan STANDARDS_PLAN --technologies-plan TECHNOLOGIES_PLAN --licenses-plan LICENSES_PLAN --authority-plan AUTHORITY_PLAN --emit-plan DIRECTORY
promin --root PROJECT init --standard-bundle BUNDLE --preset PRESET --project-plan PROJECT_PLAN --standards-plan STANDARDS_PLAN --technologies-plan TECHNOLOGIES_PLAN --licenses-plan LICENSES_PLAN --authority-plan AUTHORITY_PLAN --review-plan
promin --root PROJECT init --standard-bundle BUNDLE --preset PRESET --project-plan PROJECT_PLAN --standards-plan STANDARDS_PLAN --technologies-plan TECHNOLOGIES_PLAN --licenses-plan LICENSES_PLAN --authority-plan AUTHORITY_PLAN --dry-run
promin --root PROJECT init --standard-bundle BUNDLE --preset PRESET --project-plan PROJECT_PLAN --standards-plan STANDARDS_PLAN --technologies-plan TECHNOLOGIES_PLAN --licenses-plan LICENSES_PLAN --authority-plan AUTHORITY_PLAN
promin --root PROJECT init --standard-bundle BUNDLE --preset PRESET --project-plan PROJECT_PLAN --standards-plan STANDARDS_PLAN --technologies-plan TECHNOLOGIES_PLAN --licenses-plan LICENSES_PLAN --authority-plan AUTHORITY_PLAN --activation-proofs ACTIVATION_PROOFS
```

The first command validates all five supplied plans and atomically emits their
canonical forms. It does not synthesize plan values from a project ID or source
root. Review validates supplied plans and identities without mutation; dry-run
also performs configured provider preflight. Successful observations are
digest-bound in a transient in-memory preflight receipt. That receipt is never
an initialization record and is never written under `.promin/init/`. The fourth
and fifth commands perform the one atomic state mutation for local-owner and
team-signed trust, respectively.

Plain initialization persists exactly five records under `.promin/init/`:

```text
project.json       ProjectInit
standards.json     StandardsInit
technologies.json  TechnologiesInit
authority.json     AuthorityInit
activation.json    Activation
```

`licenses.json` is a required validation input and is not a sixth installed init
record.

The plan directory is not `.promin/`; emit, review, and dry-run MUST leave the
project control directory absent when it did not exist before the command.
The product repository MUST NOT require a root `core/`. Installed authority is
the exact immutable copy below `.promin/standard/<digest>/`.

## Ingress

Every record entering command, import, replay, rebuild, or export processing
follows:

```text
bounded canonical parse
-> compiled structural schema
-> semantic policies
-> Activation and implementation-closure integrity
-> capability and conjunctive effect scope
-> current Grant, separation of duties, Lease, and fence where required
-> Candidate and evidence binding
-> one bounded atomic event batch
-> rebuildable projection
```

Empty, unknown, null, stale, degraded, unbound, replayed, or
implementation-drifted critical records reject.

## Grants, separation, and leases

Default is deny. Bootstrap binds configured roots, capability ceilings, and the
exact Activation. Every Grant binds subject, capability, conjunctive effect
scope, nonce, not-before and expiry, revocation state, bounded delegation, the
child signed claim, and either the one bootstrap proof, an active exact
`authority.manage` issuer Grant claim, or the configured team-signature
boundary. Maximum delegation depth is eight.

Apply all five separation-of-duty rules at Grant issue time and action time.
Resolve revocation Decisions and Events as immutable exact records; an arbitrary
Decision ID is not a revocation proof.

A mutation Lease binds Task, Activation, Candidate, context and WorkCard
digests, separate manager and holder Grant claims, generation, monotonically
increasing fence, heartbeat, expiry, and close acknowledgement. `ACTIVE` and
`CLOSING`, and `EXPIRED` or `REVOKED` without recorded reconciliation, occupy
capacity. A Lease grants no validation, resolution, waiver, promotion,
distribution, acceptance, or public approval. Task, Finding, GateResult, and
Decision transitions validate the current event-time state.

## Verified inventory stream

The public inventory boundary is a verified immutable JSONL stream plus its
manifest, not a caller-authored collection of entries.

Required invariants:

```text
one accepted raw file -> one derived Artifact proxy
normalized relative path supplied by runtime
content digest supplied by runtime
data_class = untrusted-source
rolling stream SHA-256, byte count, and entry count
manifest binds Candidate and provider identity
one-pass verification and projection input
atomic projection publication
inventory pass count = 1
rebuild product pass count = 0
peak memory amplification <= 32x stream bytes
search_text_bytes_max = 4096 per row
```

Inventory never synthesizes `Task`, `READS`, or `PRODUCES` facts. Tasks and
relations require explicit semantic input. `immutable-vcs-tree` may be
creditable only when provider-proven. `observational-best-effort` is always
explicit and non-creditable.

## Bounded search

For internal bounded retrieval operations, exact ID resolution precedes ranked
lookup. Non-exact lookup MUST select at most the configured top-k seeds. When
further matches exist, return:

```json
{
  "refinement_required": true,
  "refinement_hints": ["bounded operator hints"],
  "unselected_matches_traversable": false
}
```

Do not paginate the corpus. Typed closure traversal starts only from selected
seeds. Continuation pages MUST equal the complete union of the selected typed
closure, without omission or duplication. Query content is bounded untrusted
data. A missing term returns an empty result without fallback widening.

## Current ready frontier

`ReadyFrontier` is live-only and non-authoritative. Reject every `DEPENDS_ON`
cycle at command, import, replay, and rebuild ingress. A Task enters the frontier
only when all of these predicates hold against the same current HEAD:

```text
Task.state = READY
every DEPENDS_ON target is currently COMPLETED
every required GateResult is current and has outcome=pass and pass_credit=true
GateResult binds the current Activation, Candidate, and GateRunDefinition
no current OPEN Finding blocks the Task
```

Order by `created_at` ascending and `task_id` ascending. Continuation is
deterministic. Any truncation MUST be explicit. `next` derives this frontier,
selects at most its first Task, and returns that Task as an immutable read-only
`WorkCard` inside `NextResult.work_card`. `continue` consumes the opaque
ReadyFrontier token and returns the next strict `ContinueResult`. Neither command
may approximate the frontier with FTS text matching.

## Compact continuation

Continuation is local derived state, not authority. A caller-visible opaque
token MUST be at most 256 bytes. Its digest-bound local state MUST be at most
16 KiB. Continuation metadata MUST be no more than 10% of the containing bounded
WorkCard.

The authenticated state binds and rechecks:

```text
Activation
subject
current projection.read Grant ID and claim digest
capability projection.read
selected ReadyFrontier and deterministic order
frontier cursor
authoritative HEAD and sequence
projection digest
complete budgets
issued-at, expiry, and TTL
Grant revocation state
```

The public `NextResult.continuation` and `ContinueResult.continuation` fields
carry only this ReadyFrontier next-page token and are null when the frontier page
is complete. Separately, `RetrievalPage` is the generic bounded-retrieval result,
owns generic retrieval continuation, and exposes only `stream_cursor` and
`next_stream_cursor`; `seed_cursor` and `next_seed_cursor` reject as removed
compatibility fields. Its token is not ReadyFrontier scheduling continuation.
`WorkCardProjection` is internal selected-Task materialization and MUST contain
no continuation field or token.

The per-Activation secret and continuation state live below `.promin/state/`
and are excluded from standard-distribution outputs. Changed authority, HEAD,
projection, ranking, budget, subject, or time binding rejects resume.

## Events, projections, and evidence

Events are authority. SQLite, typed graph state, checkpoints, WorkCards, health
reports, inventory proxies, and continuation state are disposable projections.

`EventStorePolicy` is rebuilt live from the installed AuthorityModel and
SemanticModel before normalization, mutation, and replay. It has no defaults or
nullable critical fields. Under the cross-process writer lock, refresh exact
HEAD and replay-derived authority state, verify the installed bundle and
provider receipts, authorize and apply the command to a copy, compute the typed
state-binding delta, durably append, then publish the new live state. A failed
append MUST NOT mutate published state.

Every EventBatch MUST bind:

```text
previous_authority_commitment
authority_commitment
cumulative_event_count
event_semantic_digest
non-empty sorted unique state_binding_delta over changed typed leaves
cumulative_state_binding_update_count
state_binding_digest using typed-sparse-merkle-v1
UTC-second created_at
```

The authority commitment covers the previous commitment, sequence, previous
batch digest, event count, event semantic digest, state-binding update count,
and state-binding root. Publication requires local-writer locking, file sync,
atomic replace, directory sync, and crash recovery. Replay verifies the complete
journal prefix. A
checkpoint or sidecar may accelerate verification but MUST NOT supply or replace
an authoritative commitment or state leaf.

Evidence is immutable CAS content bound to exact Candidate, policy, tool,
inputs, implementation closure, and invoked adapter identities. Failed,
blocked, stale, unresolved, degraded, or drifted evidence receives no pass
credit.

Credit resolves both exact `artifact_id` and finalized
`artifact_record_digest`. It also checks `evidence_class` and
`evidence_purpose`; `harness-generated` cannot satisfy a
`product-execution` GateRunDefinition. Pass, fail, and blocked statuses require
exact Artifact bindings; skipped requires a reason, carries no Artifact credit,
and has `pass_credit=false`. A GateRunDefinition is immutable Task-owned input
committed before a Run or gate command and fixes expected class, purpose,
product-credit requirement, target kind, digest and scope, Candidate, policy, tool, provider, and
inputs. Inline gate definitions and payload-digest substitutes reject.

`doctor` is the only aggregate health output. It is derived and always reports
`report_authoritative=false` and `pass_credit=false`. Health and projection
metrics cannot grant authority, acceptance, distribution, or public-approval
credit. The report exposes no token, cost, or usage metrics and no goal, session,
batch, workspace, per-run usage, or per-run allocation.

## Live health and metrics

`DoctorResult` has exactly these current components:

```text
core init providers recovery replay projection
```

Component and rollup statuses are exactly `healthy`, `degraded`, `failed`, or
`incomplete`, with precedence `failed`, `incomplete`, `degraded`, `healthy`.
`--no-replay` makes replay and rollup incomplete. A missing projection is
incomplete; a stale or contradictory projection is incomplete or failed, never
healthy. Provider health derives from actual configured bounded healthcheck
observations. Archival diagnostics have no effect on current health.

Doctor metrics are limited to `core_artifacts_verified`, `init_records_verified`,
`provider_healthchecks_executed`, `event_batches`, `projection_entities`, and
`projection_relations`. Product scans equal zero.

`OperationMetrics` is a live-only non-authoritative observation for one command.
Allowed groups are duration, changed records, event write, projection update,
runtime checkpoint, physical payload bytes, and bytes per changed record. Both
record types reject token, cost, usage, or goal/session/batch/workspace/per-run
allocation fields. They always provide no authority or pass credit.

## Research draft sanitation

`ResearchDraftIntake` is strict transient ingress. Its canonical JSON is at
most 1 MiB; source payloads are individually at most 16 MiB and together at
most 64 MiB. Every source binds source ID, trusted locator, provenance digest,
immutable Artifact ID and record digest, recomputed content digest, exact size
and media type, and the active LicensesPlan digest. An allowed source requires a
reviewed or source-verified license binding.

Allowed claim kinds are `research_question`, `hypothesis`, `assumption`,
`evidence_claim`, and `blocked_claim`. Verification status is one of
`unverified`, `source-bound`, `verified`, or `blocked`. `citation_refs` identify
research sources; `evidence_refs` identify independently resolved Artifact
records. Missing payload receipts are `metadata-only`; every dependent claim
remains blocked and `normative_use_allowed=false`.

`SanitizedResearchDraft` admits only eligible source-bound or independently
verified factual candidates. Distribution, marketing, and proof claims remain
excluded. Its exclusion ledger retains bounded claim text and digest, source and
evidence references, and reasons. The result is live-only, derived, and always
keeps pass credit and product acceptance false and public approval not approved.
It also keeps `public_release_approved=false`.

## Import, export, and rebuild

Command, import, replay, rebuild, and export each require bounded canonical
parse, compiled Draft 2020-12 validation, and semantic validators. Reject empty,
unknown, null, stale, degraded, unbound, cyclic, or implementation-drifted
critical records. Derived runtime policies and results are never imported as
authority.

`SemanticExport` is export-only with `export_kind=semantic-state`; it is not a
package or archive. It binds Candidate, Activation, exact HEAD, Core, preset,
implementation closure, provider receipt, input digests, and an actual output
Artifact ID and finalized record digest. Recompute its output digest, byte size,
media type, and `SemanticStatePayload` from the exact CAS bytes before
acceptance. Deduplicate exported records by exact record digest and order them
by digest ascending. Projection rebuild verifies journal and inventory
inputs, performs zero product passes, and atomically publishes a rebuildable
view.

## Provider protocols

The semantic owner defines exactly nine protocols:

```text
promin.control-runtime.v1
promin.shape-validation.v1
promin.content-identity.v1
promin.local-serialization.v1
promin.query-projection.v1
promin.filesystem-inventory.v1
promin.export-scan.v1
promin.signature.v1
promin.build-dependency.v1
```

Each operation MUST match the Core-owned request and response contract and an
installed content-addressed dependency receipt. `ProviderInvocationEvidence`
binds exact protocol ID, operation, operation-contract digest, provider and
adapter identity, invocation kind, and dependency-receipt digest. Full provider
output binds exact `output_digest`, `output_size_bytes`, and
`output_size_ceiling_bytes`; diagnostic stdout/stderr captures are separate,
bounded to 1 MiB, and carry explicit truncation flags. Unknown bindings,
reconstructed receipts, and raw provider-specific bypasses reject.

## Candidate, evidence, decision, status

The only valid distribution chain is:

```text
exact immutable candidate ZIP bytes
-> external StandardReleaseCandidateBinding
-> physical typed evidence resolution
-> external StandardReleaseEvidenceManifest
-> configured Ed25519 signed approve/reject StandardReleaseDecision
-> derived StandardDistributionStatus
```

### CandidateBinding

Validate exact shape, structural SemVer, self-digest, archive SHA-256 and byte
length, archive member manifest, package manifest, checksums, Core, preset,
package tool, validator, test manifest, and portable implementation closure.
The binding MUST describe the exact supplied archive bytes.

### EvidenceManifest

Each entry binds an evidence role, relative path, SHA-256, exact record type,
`pass` status, CandidateBinding digest, and explicit JSON predicates. Resolve
every path below the explicit evidence root and reject escapes, aliases,
normalization/case collisions, links, and non-regular files. Read each record
once with bounded size and depth, verify unchanged file identity, hash and parse
the same byte buffer, and evaluate exact role-specific predicates. A record that
changes during ingress rejects rather than being reopened.

Required roles are:

```text
linux
windows
physical-scale
saturation-audit
human-documents
linux-no-degradation
windows-no-degradation
```

All roles MUST be present and physically resolved. A digest string without the
corresponding validated record provides no credit.

### Decision

The external decision exact shape includes:

```text
decision_id
standard_name = promin
version = CandidateBinding.version
candidate_binding_digest
evidence_manifest_digest
outcome = approve | reject
decider_id
release_capability = standard.distribute
trust_root_id
signature_provider_id
key_id
nonce
decided_at
signed_claim_digest
signature
```

Require the external `StandardReleaseTrustConfiguration`, algorithm Ed25519,
provider `cryptography-ed25519-v1`, matching trust root, active matching key,
matching decider, exact capability, validity window, revocation check,
anti-replay nonce, canonical signed claim digest, and valid signature. Also
require a separately supplied SHA-256 pin for the exact trust-configuration
bytes. A valid signature under an unpinned caller-supplied root has status
`signature_valid_under_supplied_root` and MUST NOT approve. Unknown, unsigned,
stale, replayed, mismatched, unpinned, or unconfigured decisions reject.

### Derived status

No decision yields `candidate`; a verified approve yields `approved`; a
verified reject yields `rejected`; a supplied invalid decision yields
`invalidated`. No file inside the ZIP may predeclare these results.

Every status preserves:

```text
product_acceptance_pass = false
product_public_approval = not_approved
```

Cutover and deletion are external operational decisions. They require current
candidate-bound dual-run parity, deterministic rollback and recutover, all P0/P1
Findings closed, zero remaining legacy references, and an explicit authorized
human Decision. A one-time importer remains outside the canonical tree and may
migrate supported Tasks, Grants and revocations, Leases, evidence Artifacts,
Findings, GateResults, Decisions, and continuation state through strict ingress;
projections, indexes, reports, and databases are rebuilt. Source reference
material remains read-only. In the current package state, cutover is false and
deletion is false; source reference material is never deleted or copied into the
standard as normative content. `public_release_approved` remains false.

## Package operations

Use only `tools/promin_package.py`:

Run the Windows platform command on Windows and the Linux platform command on
Linux. Each command observes its current installed environment.

```text
python tools/promin_package.py verify-tree ROOT --install-mode current-environment
python tools/promin_package.py build ROOT ARCHIVE --candidate-binding-output CANDIDATE_BINDING --install-mode current-environment
python tools/promin_package.py verify ARCHIVE --candidate-binding CANDIDATE_BINDING --install-mode current-environment
python tools/promin_package.py verify-platform ARCHIVE CANDIDATE_BINDING WINDOWS_RESULT --install-mode online-clean
python tools/promin_package.py verify-platform ARCHIVE CANDIDATE_BINDING LINUX_RESULT --install-mode online-clean
python tools/promin_package.py build-evidence-manifest ARCHIVE CANDIDATE_BINDING EVIDENCE_ROOT EVIDENCE_PLAN TRUST_CONFIGURATION EVIDENCE_MANIFEST --expected-trust-root-sha256 288fbbb704a905a193088d470f1907c1798098eca903800202396c4a65e89466
python tools/promin_package.py build-document-evidence ROOT ARCHIVE CANDIDATE_BINDING VISUAL_REVIEW RENDER_ROOT DOCUMENT_EVIDENCE --font-regular PATH --font-regular-sha256 SHA256 --font-bold PATH --font-bold-sha256 SHA256 --font-italic PATH --font-italic-sha256 SHA256 --font-mono PATH --font-mono-sha256 SHA256
python tools/promin_package.py sign-decision ARCHIVE CANDIDATE_BINDING EVIDENCE_MANIFEST EVIDENCE_ROOT TRUST_CONFIGURATION PRIVATE_KEY DECISION --decision-id ID --outcome <approve-or-reject> --decider-id ID --key-id ID --decided-at UTC
python tools/promin_package.py verify-closure ARCHIVE CANDIDATE_BINDING EVIDENCE_MANIFEST EVIDENCE_ROOT DECISION TRUST_CONFIGURATION --expected-trust-root-sha256 OPERATOR_PINNED_SHA256 --install-mode current-environment
```

`build` creates candidate bytes only. CandidateBinding, evidence, evidence
manifest, trust configuration, private key, and decision remain outside the ZIP.
Exact-package verification is recomputed from `ARCHIVE`; multi-platform closure
is recomputed from the exact Windows and Linux records. Neither is a supplied
evidence role. `verify-closure` derives status after verifying every preceding
stage. A second build from the same canonical tree MUST have the same SHA-256.

Platform/Python matrix rows are audit-level compatibility observations. They
are non-authoritative, provide no standalone pass credit, and cannot authorize
distribution or product acceptance. Supplemental interpreter rows do not add
roles to the exact seven-role EvidenceManifest. The manifest additionally
resolves the exact eight-lane CPython 3.12/3.13/3.14 matrix and all four CPython 3.14
supplemental records by relative path, SHA-256, and byte count. Their signed
completion times, plus every nested physical completion, participate in the
derived maximum evidence completion time.

## Dependency modes

| Mode | Interpreter and source |
|---|---|
| `current-environment` | current interpreter; no nested environment |
| `offline-wheelhouse` | clean temporary environment; explicit local wheels only |
| `online-clean` | clean temporary environment; declared online dependencies |
| `none` | dependency smoke omitted with no pass credit |

## Validation selection

Focused lane:

```text
python -m pytest -q -m "not scale"
```

Physical lane:

```text
PROMIN_SCALE_WORKSPACE=<dedicated-workspace> python -m pytest -q -m scale
```

On PowerShell, set `$env:PROMIN_SCALE_WORKSPACE` before the physical command.
Selecting `-m scale` without that environment value MUST fail, not skip. The
physical lane creates or verifies 100,000 files through the production
inventory, projection, and query route. It does not run a 1000 by 1000 matrix.
Raw inventory MUST yield exactly one Artifact proxy per file and MUST yield no
Task or Relation semantics. An explicit authorized harness corpus MUST produce
at least 198,999 Core-valid typed Relations. The workload MUST execute at least
600 actual runtime queries mixing exact Artifact/Task IDs, content-only and
high-cardinality terms, broad bounded
refinement, misses, hostile identity text, and forced continuation across depth
1-12. Token, persisted-state, complete selected-closure union, and silent
truncation bounds are executable predicates.

Required no-degradation tests must execute. A skipped required test is a failed
no-degradation result. Platform, package, PDF, scale, and no-degradation records
must bind the same exact CandidateBinding.

Creditable no-degradation MUST cross-bind all of the following:

```text
controller platform, release, machine, sys.platform, and profile key
CPython implementation, full version, ABI tag, and platform tags
clean-venv executable below its venv prefix and its SHA-256
base executable below its base prefix and its controller-matching SHA-256
one SQLite version across platform binding, validation, and installed probe
```

One monotonic total deadline covers setup, source and wheelhouse copies, clean
environment creation, dependency installation, every installed-runtime probe,
validation, and required tests. Every child is placed in an OS process-tree
boundary. Timeout or normal parent exit closes remaining descendants. Deadline
exhaustion, captured-output overflow, an orphaned descendant, missing progress,
or phase-budget exhaustion fails and receives no pass credit.

The evidence runners use these exact argument shapes:

```text
python tools/promin_no_degradation.py ROOT NO_DEGRADATION_RESULT --archive ARCHIVE --install-mode offline-wheelhouse --wheelhouse WHEELHOUSE --candidate-binding CANDIDATE_BINDING
python tools/promin_saturation.py PHYSICAL_WORKSPACE SATURATION_OUTPUT_DIRECTORY --archive ARCHIVE
python tools/promin_saturation_audit.py ROOT AUDIT_OUTPUT_DIRECTORY PHYSICAL_WORKSPACE --archive ARCHIVE --physical-evidence-private-key PHYSICAL_PRIVATE_KEY --physical-evidence-trust-configuration TRUST_CONFIGURATION --physical-evidence-key-id PHYSICAL_KEY_ID --physical-evidence-producer-id PHYSICAL_PRODUCER_ID
```

`SATURATION_OUTPUT_DIRECTORY` contains `saturation-result.json` and
`AUDIT_OUTPUT_DIRECTORY` contains `saturation-audit.json`. Configure the audit
process-level `PROMIN_EVIDENCE_*` variables for the `saturation-audit` producer.
The four physical arguments configure only the nested `physical-scale`
producer. Both producers MUST use distinct keys and subjects from the same
pinned trust configuration; partial or mixed configuration is rejected before
tests or scale work starts.

For each full saturation iteration, move the incoming `.promin` to a
byte-identified baseline, create a new exact five-record initialization with
zero product scans, and restore only the bounded physical recipe. Semantic state
MUST NOT be reused. Preserve every completed iteration control state separately,
then restore the exact baseline before publishing final evidence.

The package root, physical workspace, audit output, active `.promin`, and
operational-state root MUST be mutually disjoint. Published evidence and logs
belong only to `AUDIT_OUTPUT_DIRECTORY`. Recoverable baseline and iteration
control states belong only below the workspace sibling
`.<workspace>.promin-saturation-audit-state/`; they are not evidence payloads.
Partial progress is uncredited. Publish `saturation-audit.json` only after three
consecutive full zero-new iterations.

Every required subprocess has a monotonic duration, bounded captured stdout and
stderr, a per-command timeout, process-group termination, and an overall lane
budget. Timeout, overflow, orphaned descendants, missing progress, or budget
exhaustion fails the result and receives no pass credit.

## PDF verification

`HumanDocumentVerification` binds the exact candidate ZIP, every PDF path,
SHA-256, byte length, page count, extracted character count, blank-page and
extraction diagnostics, the exact regular/bold/italic/mono font digests,
deterministic rebuild identity, and a rendered PNG for every page. Its visual
review record binds every rendered-page digest and clipping result. A PDF header,
first-page sample, or non-empty byte count alone receives no credit.

The document cover identity is limited to MOROK TOWER, `promin`, and the footer
`version 1` or `версія 1`. Operational evidence, decisions, and generated
diagnostics remain outside the canonical package.
