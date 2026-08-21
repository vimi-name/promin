# Public Workflow and Tooling Design

## Status

Proposed architecture approved in chat on 2026-08-21.  This document defines
the implementation boundary; it does not claim product acceptance, language
tool execution, platform acceptance, or performance acceptance.

## Purpose

Promin remains a small, open management standard for complex agent work.  Its
public surface must make a safe first-use path easy while preserving the
explicit control, deterministic evidence, and recovery boundaries needed by
experienced operators.

The current implementation already has a deterministic minimal initializer,
an expert selection bundle, bounded inspection APIs, recovery/revalidation
primitives, and declarative language capability profiles.  The missing public
vertical slice is that these pieces do not yet form a discoverable, ordinary
CLI workflow and the language declarations do not yet produce tool receipts.

## Goals

1. A minimal, deterministic initialization can create the local control layer
   and an initial bounded work proposal in one explicit command.
2. An experienced operator can supply a complete expert bundle and exact
   language/tool selections without hidden inference.
3. Inspection, clean reinitialization, revalidation, reconsolidation, and
   reporting are public, evidence-bound workflows rather than Python-only
   primitives.
4. C/C++, C#, and JVM profiles can use already-installed open-source tools by
   explicit selection and receive immutable local evidence of probe or
   invocation results.
5. No route installs software, chooses tools from a model response, treats a
   declaration as availability, or promotes a result to acceptance.

## Non-goals

- No release version change.
- No automatic package installation, network download, remote execution, or
  mutation of a user project without an explicit authority-bearing command.
- No language-specific compiler/build success claim from profile selection.
- No replacement for external tool output with a Promin-generated proxy.
- No platform, 100k, or performance acceptance claim in this wave.
- No OS-specific sealing or hostile-actor machinery in Promin v1.

## Design

### 1. Guided initialization and first-work proposal

`promin init --yes` retains the existing minimal deterministic control-layer
creation.  A new explicit `--initial-work` mode joins the already implemented
bounded initial-project-work route to initialization:

- `none` preserves current init-only behavior;
- `plan` emits the deterministic proposal without applying init;
- `prepare` applies the requested init and then performs the existing bounded,
  read-only inventory plus proposal route.

The default for an explicit `--yes --init-experience minimal` invocation is
`prepare`.  It may write Promin control/evidence only; it never mutates source,
installs software, invokes a model, or executes a proposed task.  The result
must expose `project_mutation_performed`, first-work status, exact plan and
proposal digests, and false acceptance/pass fields.

Expert init keeps exact `expert-init.json` input and never inherits the
minimal default.  Expert mode must explicitly choose any initial-work behavior
and exact language tool selections.

### 2. Public operation commands

Add public commands to the existing `promin` CLI, with JSON as the only stable
machine interface:

| Command | Behavior | Effects |
| --- | --- | --- |
| `promin inspect` | Calls bounded product inspection and prints client-safe and machine-safe facts. | Read-only; no provider, build, SQLite, or project writes. |
| `promin recover clean` | Plans or, with explicit authority and `--apply`, invokes clean reinitialization through the existing verified/quarantine/rollback operation. | Create-only receipts and controlled local state changes only. |
| `promin revalidate` | Replaces the doctor-only entry point while retaining its strict input identity and recorded-read-only limitations. | Plan-only by default; receipt creation only when authority and exact workflow permit it. |
| `promin report` | Produces canonical client-safe JSON from inspection and workflow receipts. | No promoted claims; file output is create-only when explicitly requested. |

The previous `doctor --revalidate` remains a compatibility alias.  `REPAIR`
continues to require an explicit public clean-recovery request and cannot be
smuggled through recorded observations.

### 3. Open-source language tool adapters

Add a domain-named `language_tooling` module.  It consumes only the existing
strict language profile catalog and an explicit operator selection.  It has
three separate actions:

1. `plan`: resolve selected tools and exact bounded argv without process
   execution;
2. `probe`: verify an already-installed executable identity and version with
   a bounded, allow-listed argv;
3. `run`: execute one explicitly selected, profile-declared static or
   documentation action against a bounded project path.

Initial adapters cover only the exact declarative tools already named by the
bundled profiles:

- C/C++: `clang-tidy`, `clang-doc`, `doxygen`;
- C#: `dotnet`, `docfx`;
- JVM: `javac`, `javadoc`, `checkstyle`, `spotbugs`.

Every probe/run records executable file identity, argv, working directory
identity, start/end time, stdout/stderr digests and sizes, exit code, profile
digest, selected capability ID, and a false-credit result.  The action rejects
unknown profile references, non-canonical paths, executable drift, arguments
outside the declared action, network access, and project mutation outside
declared output roots.  Tool results remain diagnostic until a separate
project-owned verification rule consumes them.

### 4. Recovery and report data flow

```
strict CLI input
  -> canonical request / authority binding
  -> existing recovery or revalidation primitive
  -> create-only receipt
  -> product inspection / report serializer
  -> client-safe JSON
  -> optional external PDF renderer
```

The client PDF is intentionally an external presentation artifact generated
only after evidence collection.  It binds the report JSON digest and labels
all missing, failed, diagnostic-only, or unaccepted evidence.  It is not an
authority source and cannot change product state.

## Failure behavior

- Unavailable selected executable: structured `UNAVAILABLE`, with no implicit
  substitute.
- Tool failure or timeout: structured failure receipt, no retry hidden from
  the receipt, no acceptance credit.
- Interrupted clean recovery: existing rollback/quarantine semantics remain
  authoritative; partial reinitialization is never reported as success.
- Invalid receipt, unknown language profile, stale plan, input drift, or
  authority mismatch: fail closed before external tool execution.
- Client report/PDF creation failure: preserve prior create-only evidence;
  emit no positive report claim.

## Files and ownership for implementation

- `promin/__main__.py`: public parser and dispatch only.
- `promin/initial_project_work.py`, `promin/experience.py`: init-to-proposal
  binding, without duplicating planner logic.
- `promin/clean_reinitialization.py`, `promin/revalidation_workflow.py`:
  explicit public request adapters only; existing authority primitives remain
  owners of state transitions.
- `promin/product_inspection.py`: canonical report input serialization only.
- `promin/language_tooling.py` (new): profile-declared tool planning, probing,
  bounded execution, and receipt emission.
- `tools/promin_client_report.py` (new): external evidence-bound JSON-to-PDF
  presentation tool; never imported by Core.
- Focused public workflow, language tooling, recovery/reporting, and client
  report tests; relevant Ukrainian documentation and package inventory.

## Verification plan

1. RED/GREEN public CLI tests for minimal `init --yes --initial-work prepare`,
   expert explicit override, and no source mutation.
2. RED/GREEN clean recovery CLI tests for plan, missing authority, rollback,
   and create-only receipt behavior.
3. RED/GREEN inspection/report CLI tests proving client output never promotes
   claims.
4. Per-language fixture tests using controlled already-installed fake tools:
   plan/probe/run receipt identity, unavailable tool, argv rejection, timeout,
   output-root escape, and executable drift.  These establish adapter
   correctness but not host tool availability.
5. Real host tool receipts only for tools detected as installed; missing tools
   remain unavailable.  No automatic installation occurs.
6. Targeted Tier-A shards, integrity refresh, clean same-version commit, then
   a fresh isolated candidate.  Historical r6/r7/r8 and interrupted r9 roots
   remain preserved and receive no reuse or pass credit.
7. Only after a terminal exact 100k plus independent audit: Windows aggregates,
   actual modeled Linux/WSL, 72-bucket comparison, product inspection, and
   client PDF.

## Acceptance boundaries

This design can establish public workflow functionality and adapter evidence.
It cannot by itself establish language build quality, Linux-host acceptance,
12B-model execution, comparative superiority, or 100k performance.  Each
remains false until its own live evidence chain is complete.
