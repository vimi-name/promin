# Init і capability profiles

Promin `1.0.0-alpha.4` має два публічні способи ініціалізації: мінімальний для
звичайного користувача та повністю явний expert route. Обидва створюють
детермінований план і не надають authority, acceptance або pass credit.

## Мінімальний init

`promin init --yes` використовує evidence-first `minimal` profile. Bounded
preflight читає тільки заявлений проєктний контур і вибирає мовні profiles лише
з фактично знайдених технологій:

- C/CMake/C++ → `c`, `cpp`;
- .NET → `csharp`;
- JVM → `java`;
- JavaScript/TypeScript/Node → `javascript`;
- Python → `python`.

Якщо мовного або toolchain evidence немає, plan лишається на
`general-development` і записує material unknown. Відсутність даних не
перетворюється на C-family чи model inference. Tool selection також не означає,
що executable встановлений або пройшов перевірку.

Minimal init зберігає малу базову форму: один canonical owner, Core capability
bindings, resolved profile, detected facts, planned operations і digest. Він не
запускає слабку модель, не встановлює залежності та не виконує майбутні tasks.

Команда `promin init --yes --init-experience minimal --initial-work prepare`
створює лише bounded control/evidence contour і proposal. Вона не мутує source,
не встановлює tools, не викликає model і не виконує запропоновану роботу.

## Expert init

Expert route приймає повні явні choices для кожної обраної мови:

```text
promin init --init-experience expert \
  --capability-language python \
  --capability-selections expert-selections.json --yes
```

Selection фіксує `capability_id`, documentation references, tool references і
джерело рішення. Required reference не можна мовчки прибрати, а невідомі IDs
відхиляються. Profile precedence детермінований:

```text
standard default
→ host profile
→ project-package default
→ CLI override
→ interactive-user choice
```

Для перенесення повної конфігурації є один canonical expert document:

```text
promin init --expert-bundle DIRECTORY [--yes | --plan-only]
```

Directory містить рівно `expert-init.json`. Один record включає standard
profile, precedence overrides, profile-keyed language selections, plan inputs,
false claims і `bundle_digest`. `language_catalog.py` є єдиним джерелом
language/profile/tool definitions; expert init не підтримує окремий hardcoded
каталог. Legacy language-keyed input є лише адаптером, а canonical result завжди
profile-keyed.

Import повторно розв’язує expert plan тим самим resolver, тому document є
відтворюваним config input, а не готовим результатом. Він не пробує host tools,
не запускає tasks і лишає
`authority_granted=false`, `acceptance_pass=false`, `pass_credit=false`.

## Явна перша робота після init

Plain `init` не запускає post-init роботу. Після успішної ініціалізації
користувач може окремо запросити:

```text
promin next --initial-work plan
promin next --initial-work execute
```

`plan` не пише evidence. `execute` виконує bounded read-only inventory,
semantic summary і greenfield/project baseline, після чого публікує
proposal-only record у `.promin-host/initial-work/<workflow_digest>`.

На свіжому root `init --initial-work plan` повертає
`InitialProjectWorkPreview` з `activation_status=PENDING_INITIALIZATION`.
Це preview майбутньої роботи, а не activated plan.

Складність майбутньої роботи не обмежується цим baseline. Proposal зберігає
high-level goal і може бути виконаний без декомпозиції або пізніше розкладений у
детермінований DAG bounded cards із меншим контекстом для слабших workers. Він не створює Core
`Task`, `WorkCard`, `Grant` чи `Lease` і не змінює product source.

Inventory керується явними `max_files` і `max_bytes`; перевищення дає
`INCOMPLETE_RESOURCE_LIMIT` та можливість повторити route з новими limits, а не
обрізане успішне твердження. Однакові plan і inputs дають однакові IDs, порядок,
digests та receipts.

## Межа відповідальності

Promin перевіряє семантичні правила, deterministic records, budgets,
dependencies і evidence bindings. Weak-worker lifecycle є неавторитетною
Core-compatible проєкцією з task-state vocabulary `PLANNED`, `READY`, `LEASED`,
`RUNNING`, `COMPLETED`, `BLOCKED`, `CANCELLED`; він не мутує authoritative
Domain state і не набуває Domain `Lease`. Авторитетні `TaskTransition` та
`Lease` лишаються окремим Core/Domain route.
Кожний source task компілюється в одну execution card
`<source-task-id>:execute` із declared task mode/scope та optional resources.
Pause, executor failure, terminalized interruption та очікування owner не
створюють паралельних states: це typed `BLOCKED` reasons. `resume_task` або
owner approval повертає task у `READY`; cancel або owner decline переводить
його в `CANCELLED`.

Time, context, output, attempt, parallelism і workflow budgets декларуються в
плані та передаються executor як конкретні limits. Durable `started.json`
проєктує `LEASED` і `RUNNING`. STARTED-only attempt лишається `RUNNING` без
synthetic receipt; лише після caller confirmation, що executor зупинено,
`recover_interrupted(...)` може створити terminal interruption record. Якщо
crash стався після `output.bin`, recovery зберігає точні bytes і зв’язує їх
digest у receipt.

Same-process workflow boundary серіалізує persisted PAUSE/CANCEL admission і
terminal publication, а executor callback працює поза lock та cooperative
опитує `request.control_check()`. Aggregate `workflow_state` має окремі значення
`ACTIVE`, `OWNER_DECISION_REQUIRED`, `COMPLETED`, `CANCELLED`, `BLOCKED_FINAL`.
Захист операційної системи, права доступу, ізоляція процесів та довіра до
локального користувача є відповідальністю host/user environment. Promin не
позиціонує ці workflows як OS sandbox.

## Поточне evidence

- combined expert-init/language slice: `64 passed, 1 deselected`;
- Core task/domain contract: `31 passed`;
- weak execution + workflow slice: `44 passed`;
- weak lifecycle + focused CLI slice: `58 passed`;
- exact exception/publication/concurrent-control reproduction: `CLOSED`, `10/10`
  sequences;
- version: `1.0.0-alpha.4` / `1.0.0a4`.

Це correctness evidence для source routes. Package refresh, exact candidate,
повний Windows runtime та modeled Linux evidence ще потрібні, тому:

```text
acceptance_pass=false
performance_acceptance=false
pass_credit=false
```
