# Виконання через слабкі локальні workers

Promin підтримує довільні high-level objectives і dependency DAG. Складність
задачі не визначається розміром моделі: система зберігає початковий semantic
plan, а для обмежених workers може опційно розкласти його на bounded cards із
меншим контекстом та чіткими boundaries, не звужуючи objective.

## High-level plan

Canonical input `promin.high-level-execution-plan.v1` містить:

- стабільний `plan_id`;
- довільні task objectives;
- унікальні task IDs;
- dependency DAG;
- declared `task_mode`/scope та optional typed resources;
- acceptance predicate;
- явні task та workflow budgets.

Task order у вхідному JSON не визначає виконання. Promin нормалізує DAG,
перевіряє cycles та unknown dependencies і створює детерміновані IDs, topological
order і plan digest.

High-level plan зберігається у compiled execution record без втрати. Direct
executor може працювати з початковою складною задачею, або weak-worker route
може до компіляції застосувати optional deterministic decomposition на
контекстно вужчі source tasks. Після компіляції кожний source task має рівно одну execution card
`<source-task-id>:execute`. Ця card несе `preflight`, `execute` і `review` як
фази однієї instruction; вони не створюються як три приховані DAG nodes.
Owner-decision boundary зберігається як вимога task, а не передається executor
без рішення owner.

## Керована складність

Budget має окремі limits для:

- high-level tasks, execution cards, dependencies і resources;
- instruction, context та output bytes для task;
- attempt count і max attempt seconds;
- одночасно scheduled tasks;
- workflow seconds і сукупний workflow output.

Якщо DAG або decomposition не вкладається в declared budget, plan відхиляється.
Promin не скорочує objectives, workload чи evidence, щоб отримати успішний
status.

## Public workflow

`promin.weak_model_workflow` надає чотири явні операції:

- `prepare(...)` — скомпілювати deterministic execution plan;
- `execute(...)` — передати рівно одну ready/resumable card caller-owned
  executor integration;
- `review(...)` — відтворити task states із receipts;
- `resume(...)` — повернути ready/resumable cards, deferred task IDs та
  owner-decision task IDs без виконання.

Окремий public lifecycle API надає `pause(...)`, `resume_task(...)`,
`cancel(...)`, `resolve_owner_decision(...)` і явний
`recover_interrupted(...)`. Він будує неавторитетну Core-compatible проєкцію з
таким task-state vocabulary:

```text
PLANNED, READY, LEASED, RUNNING, COMPLETED, BLOCKED, CANCELLED
```

`FAILED`, `PAUSED`, `INTERRUPTED`, `DEADLINE_EXCEEDED`,
`OUTPUT_BUDGET_EXCEEDED` та `OWNER_DECISION_REQUIRED` є executor/control
outcomes, що нормалізуються в `BLOCKED` з typed reason, а не додатковими Core
states. Resume або owner approval повертає task у `READY`; cancel або owner
decline переводить його в `CANCELLED`.

Ця проєкція не мутує authoritative Domain state і не набуває Domain `Lease`.
Авторитетні Domain `TaskTransition` та `Lease` лишаються окремим Core/Domain
route. Promin володіє plan, DAG, IDs, budgets, dependencies, attempt numbers,
детермінованим replay проєкції та receipt validation. Caller володіє фактичним
executor та його tools. Немає прихованого model/provider discovery, automatic
fallback або самопризначеної authority.

Перед викликом executor кожний attempt durable записує `started.json` із
проєкційними переходами `LEASED`, потім `RUNNING`, без твердження про Domain
mutation або реальне набуття Lease. STARTED-only review показує task як
`RUNNING`, не створює synthetic receipt і не робить його resumable. Лише після
явного caller confirmation, що executor зупинено, `recover_interrupted(...)`
створює terminal `INTERRUPTED` receipt і проєкцію `BLOCKED` з reason
`executor-interrupted`.

Terminal attempt записує bounded `output.bin` і canonical `receipt.json`, що
зв’язує workflow, card, attempt, status, output bytes/SHA та observation. Crash
у output-only window не губить уже записаний payload: explicit recovery читає
точні bytes, не переписує їх і зв’язує той самий output digest у interruption
receipt. `COMPLETED` і `CANCELLED` не повторюються; resumable `BLOCKED`
підкоряється attempt та workflow limits.

Review і resume також публікують deterministic aggregate `workflow_state`:
`ACTIVE`, `OWNER_DECISION_REQUIRED`, `COMPLETED`, `CANCELLED` або
`BLOCKED_FINAL`. Це summary проєкції, а не новий Core task state і не authority
claim.

Executor request передає `max_context_bytes`, `max_output_bytes`,
`max_attempt_seconds`, `deadline_utc`, `cancellation_requested`,
`workflow_seconds_remaining`, `workflow_output_bytes_remaining` і caller-owned
`control_check`. Executor callback виконується поза workflow lock і має регулярно
опитувати `request.control_check()` та точний `deadline_utc`; check повертає лише
`None`, `PAUSE` або `CANCEL`, а latched persisted control не губиться. Promin не
робить OS-level preemption.

У межах одного Python process workflow-scoped serialization охоплює persisted
PAUSE/CANCEL admission і terminal publication. Якщо control був прийнятий до
publication boundary, terminal receipt мусить його відобразити; якщо publication
вже перемогла, пізній control відхиляється й не залишає суперечливого record.
Після повернення callback Promin перевіряє фактичний elapsed/output result і не
перетворює перевищення budget на успіх. Окремі host processes мають координувати
таку серіалізацію самостійно.

Кожний receipt зберігає фактичний `elapsed_milliseconds` окремо від bounded
`budget_elapsed_milliseconds`. Review/resume так само відрізняє actual
`workflow_elapsed_milliseconds` і `workflow_output_bytes` від charged/capped
`workflow_budget_elapsed_milliseconds` і `workflow_budget_output_bytes`.
Budget-exhaustion flags обчислюються з actual totals, тому overrun не ховається
за меншим charged value і не стає повторно доступним budget.

У plan, cards, receipts, review та resume незмінно:

```text
authority_effect=none
authority_granted=false
pass_credit=false
acceptance_pass=false
product_acceptance_pass=false
```

## CLI surface

Weak-worker route вкладений у `promin next`:

```text
promin next --weak-work prepare --weak-input PLAN
promin next --weak-work review --weak-input PLAN --weak-receipts DIR
promin next --weak-work resume --weak-input PLAN --weak-receipts DIR
promin next --weak-work record --weak-input PLAN --weak-receipts DIR \
  --weak-task-id ID --weak-outcome OUTCOME [--weak-authorize-current]
promin next --weak-work pause --weak-input PLAN --weak-receipts DIR \
  --weak-task-id ID
promin next --weak-work resume-task --weak-input PLAN --weak-receipts DIR \
  --weak-task-id ID
promin next --weak-work cancel --weak-input PLAN --weak-receipts DIR \
  --weak-task-id ID
promin next --weak-work owner-decision --weak-input PLAN --weak-receipts DIR \
  --weak-task-id ID --weak-decision APPROVED|DECLINED
promin next --weak-work recover-interrupted --weak-input PLAN \
  --weak-receipts DIR --weak-task-id ID --weak-confirm-stopped
```

CLI не запускає Ollama чи іншу модель з prose. `record` приймає explicit outcome,
а current-authority action потребує окремого caller confirmation. Nested actions
`prepare`, `review`, `resume`, `record`, `pause`, `resume-task`, `cancel` та
`owner-decision` доповнені `recover-interrupted`; recovery action відхиляється
без `--weak-confirm-stopped`.

## Обмежена Ollama-діагностика

На host виконано один послідовний low-load probe без download/install і без
одночасного завантаження моделей. Для `qwen2.5-coder:3b` та `llama3.2:3b`
використано ту саму synthetic WorkCard із трьома declared phases,
`temperature=0`, fixed seed, `num_ctx<=2048`, `num_predict=160`, `top_k=1`,
`keep_alive=0`.

- `qwen2.5-coder:3b` двічі повернув truncated invalid JSON і був відхилений як
  `REJECTED_MALFORMED_AFTER_BOUNDED_RETRY`;
- `llama3.2:3b` з першої спроби виконав strict contract з усіма claims `false` і
  отримав `DIAGNOSTIC_CONTRACT_CONFORMANT_NO_PASS_CREDIT`.

Після probe `/api/ps` показав нуль завантажених моделей. Evidence:

`C:\Users\ViMi\Downloads\promin-heavy-evidence\promin-alpha4-r7-weak-local-models-bounded-20260813T125805Z.json`

SHA-256:
`c1c36af09ae21e5f1dc1e0cba8dfde90864c98151833f21493d03551ddc2fe12`.

Verdict є mixed diagnostic і не доводить загальну якість моделі чи продукту.

## Межа відповідальності та evidence

Promin керує semantic workflow і resource budgets. Sandboxing executors,
process permissions, network policy й OS isolation належать host/user.

Weak execution + workflow slice: `44 passed`; weak lifecycle + focused CLI
slice: `58 passed`; exact exception/publication/concurrent-control reproduction:
`CLOSED`, `10/10` sequences. Core task/domain contract: `31 passed`. Package
refresh, повний Windows runtime та modeled Linux aggregate ще pending.

```text
acceptance_pass=false
performance_acceptance=false
pass_credit=false
```
