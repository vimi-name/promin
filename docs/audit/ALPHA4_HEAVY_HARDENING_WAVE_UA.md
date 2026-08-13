# Alpha.4 — agent-management workflows і heavy validation

## Активний обсяг

Версія не змінюється: `1.0.0-alpha.4` / `1.0.0a4`.

Хвиля охоплює:

- evidence-first minimal init і повний expert config;
- exact language catalog та OSS documentation/static-tool contours;
- initial project baseline;
- arbitrary-complexity DAG і optional decomposition для слабких workers;
- явні execute, pause, resume, review, recovery, revalidation,
  reconsolidation і reporting routes;
- continuation measurement, Windows 100k, modeled Linux та fixed comparative
  benchmark;
- product inspection і короткий client PDF після завершення evidence chain.

Mrets layer збережено, UGT additive. Proxy/stub acceptance не використовується.

## Поточний product contract

Promin є agent-management standard та init system. Він керує semantic plans,
IDs, dependency DAG, deterministic order, budgets, workflow-state projections,
receipts і no-promotion claims.

Task/objective complexity не обмежується силою одного агента. High-level plan
залишається джерелом meaning; за потреби weak-worker route детерміновано
розкладає його на bounded cards із меншим контекстом, не звужуючи objective.
Direct execution складної
задачі також лишається можливим на рівні caller-owned executor.

Складність контролюється явними limits: task/card counts, dependencies,
declared task scope/mode, optional resources, instruction/context/output bytes,
attempt count/time, parallelism, workflow time/output, inventory files/bytes,
receipt history та retry count. Перевищення budget дає typed incomplete/failure
state, а не скорочений PASS.

Promin не є OS sandbox. Permissions, process isolation, network policy, backups
і довіра до локальних executors належать host/user environment.

## Реалізований same-version source slice

- Minimal init більше не вигадує C-family profile за відсутності facts.
- Expert init переноситься одним canonical `expert-init.json`; import повторно
  виконує resolution, а canonical result є profile-keyed.
- Language catalog має exact seven-profile closure, bounded ordinary inputs і
  конкретні OSS tool contours для C/C++, C#, JVM, JavaScript/TypeScript та
  Python. `language_catalog.py` є єдиним джерелом language/profile/tool
  definitions і для expert init.
- `initial_project_work` дає explicit no-write plan або bounded inventory,
  semantic baseline і proposal-only receipt; plain init його не запускає.
- `weak_model_workflow` компілює по одній `<source-task-id>:execute` card на
  source task; `preflight`, `execute` і `review` лишаються phases цієї card, а не
  трьома DAG nodes. Workflow приймає explicit executor outcomes і відтворює
  неавторитетну Core-compatible lifecycle projection зі vocabulary `PLANNED`,
  `READY`, `LEASED`, `RUNNING`, `COMPLETED`, `BLOCKED`, `CANCELLED`. Вона не
  мутує Domain state і не набуває Domain `Lease`; authoritative
  `TaskTransition`/`Lease` лишаються окремими.
- Public lifecycle API має `pause`, `resume_task`, `cancel` і
  `resolve_owner_decision`, а `recover_interrupted` є окремою підтверджуваною
  recovery operation. STARTED-only attempt лишається `RUNNING` без synthetic
  receipt; interruption можна terminalize лише після caller confirmation, що
  executor зупинено. Output-only crash recovery зберігає точний payload.
- Caller-owned executor працює поза lock, опитує `request.control_check()` і
  точний deadline. Same-process workflow boundary серіалізує persisted
  PAUSE/CANCEL admission з terminal publication; actual elapsed/output totals
  зберігаються окремо від charged/capped budget totals.
- Aggregate projection `workflow_state` має `ACTIVE`,
  `OWNER_DECISION_REQUIRED`, `COMPLETED`, `CANCELLED`, `BLOCKED_FINAL`.
- Nested CLI surface охоплює `prepare`, `review`, `resume`, `record`, `pause`,
  `resume-task`, `cancel`, `owner-decision`, `recover-interrupted`; остання дія
  вимагає `--weak-confirm-stopped`.
- `revalidation_workflow` виконує строгий цикл
  `INSPECT → REPAIR → REVALIDATE → RECONSOLIDATE → REPORT` в одному
  plan/receipt/predecessor chain. Semantic identity не залежить від абсолютного
  path, а runtime records продовжують зв’язувати конкретні paths.
- Усі нові records зберігають authority, acceptance, product credit і pass
  credit `false`.

Поточна production-реалізація використовує portable file, JSON і SQLite
operations та покладає OS-level policy на host/user environment.

## Fresh ordinary correctness evidence

- combined expert-init/language slice: `64 passed, 1 deselected`;
- Core task/domain contract: `31 passed`;
- weak execution + workflow slice: `44 passed`;
- weak lifecycle + focused CLI slice: `58 passed`;
- exact exception/publication/concurrent-control reproduction: `CLOSED`, `10/10`
  sequences;
- strict-cycle revalidation slice: `39 passed`;
- compile/diff checks для заморожених source slices пройшли.

Continuation measurement тепер використовує portable observer реального
transient SQLite state перед public resume. Він зв’язує locator, digest і byte
count та не публікує payload. Focused continuation + raw-cardinality + storage
slice має `36 passed`; legacy compatibility — `2 passed`; saturation self-check
пройшов із `acceptance_pass=false` і `full_100k_executed=false`.

Ці результати не є full aggregate, runtime, performance або product acceptance.

## Історичне scale evidence

R2 Windows 100k був навмисно зупинений і термінально класифікований
`REJECTED_QUADRATIC_AUTHORITY_PREFIX` після evidence-bounded projection
`61.1–92.3 h`. Це довело performance blocker, а не acceptance.

R6 завершив незменшений `100000`-file / `600`-query workload до publication
stage: EventStore HEAD `1604`, `200603` events. Run був термінально відхилений
через schema seam для законного zero-byte continuation manifest. Окремо виміряні
показники не вкладалися в profile:

- semantic ingestion `5399.621207 s > 600 s`;
- commit p95/p99 `4285.4479/9164.8388 ms > 500/1000 ms`;
- query p50/p95/p99 `483.5423/589.7476/828.9208 ms > 100/150/500 ms`;
- peak RSS `1257553920 > 805306368` bytes.

Отже capacity була продемонстрована частково, але nonlinear speedup,
low-memory target і performance acceptance не доведені.

## R7: перерваний exact Windows 100k

Same-version candidate:

`C:\Users\ViMi\Downloads\promin-1.0.0-alpha.4-heavy-verified-r7.zip`

SHA-256:
`d562f8e70808b490d86f0c9477269b5ae6494fa9f375d683e4b52ac4ae7a39e5`.

Fresh root
`D:\ProminValidation\alpha4-r7-100k-d562f8e70808-20260813T120018213Z`
матеріалізував `100000` corpus files (`3977802` logical bytes), але process chain
зник під час immutable Git snapshot. `.git/index`, commit/ref/tree identity,
terminal, result, failure та phase log відсутні; journal checkpoint має нуль
batches/events, тому semantic ingestion не починався.

Причина interruption не встановлена. З цього не виводиться product failure, але
run не має terminal або pass credit, не перезапускається і не використовується
повторно.

Create-only observation receipt:

`C:\Users\ViMi\Downloads\promin-heavy-evidence\promin-1.0.0-alpha.4-windows-100k-r7-interruption-observation.json`

SHA-256:
`e26a06d456aa67724de460fb0d8ced8e81b45b53e1a3b46641cace9926e6f685`.

## Bounded Ollama diagnostic

На host послідовно перевірено дві локальні 3B models без максимального
навантаження, download або паралельного residency:

- `qwen2.5-coder:3b` відхилено після двох truncated invalid JSON responses;
- `llama3.2:3b` з першої спроби виконав strict WorkCard contract з claims
  `false`.

Після probe models були вивантажені. Evidence:

`C:\Users\ViMi\Downloads\promin-heavy-evidence\promin-alpha4-r7-weak-local-models-bounded-20260813T125805Z.json`

SHA-256:
`c1c36af09ae21e5f1dc1e0cba8dfde90864c98151833f21493d03551ddc2fe12`.

Verdict mixed diagnostic; product/model acceptance не надається.

## Обов’язкові наступні evidence steps

1. Package inventory/integrity refresh та integrated validation.
2. Одна coherent same-version commit, без push.
3. Новий deterministic r8 candidate і fresh detached exact Windows 100k.
4. Terminal audit; лише після нього Windows non-scale aggregates ×2.
5. Modeled Linux/WSL validation.
6. Fixed 72-bucket Promin vs Markdown vs empty comparison.
7. Product inspection.
8. Короткий client PDF, bound до фінальних receipts.

До завершення цих кроків очікувані product/performance результати лишаються
непідтвердженими.

## Truth tokens

```text
validation_claim=targeted_ordinary_correctness_only
runtime_diagnostic_pass=false
acceptance_pass=false
visual_acceptance=false
performance_acceptance=false
pass_credit=false
g27_g45_pass_credit=false
authority_confirmed=0
authority_pending=required_final_runs
full_static_scan_deferred=true
mrets_layer=preserved
ugt_layer=additive
proxy_acceptance=false
```
