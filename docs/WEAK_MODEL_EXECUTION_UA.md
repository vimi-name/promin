# Bounded execution для слабкої моделі

`promin.weak_model_execution` перетворює малий high-level план у
детерміновані, вузькі task cards. Це допоміжний планувальний шар для хоста з
лімітом **12B параметрів** та багатьох простих виконавців. Число 12B є лише
бюджетом декомпозиції: воно не доводить фактичну модель, її доступність,
якість відповіді або право щось виконувати.

Модуль чистий: він не запускає process/tool, не читає проєкт, не змінює файли
і не видає Grant, Lease, WorkCard або capability. Ідентифікатор tool у плані
— лише декларація, яку має окремо дозволити та виконати реальний host route.

## Вхідний план

Вхід має точну схему `promin.high-level-execution-plan.v1`:

```json
{
  "schema": "promin.high-level-execution-plan.v1",
  "plan_id": "bounded-repair",
  "budget": { "...": "bounded integer fields" },
  "tasks": [
    {
      "task_id": "inspect-source",
      "title": "Inspect source",
      "objective": "Collect scoped observations.",
      "allowed_paths": ["promin/example.py"],
      "dependencies": [],
      "risk_class": "read-only",
      "static_tool_ids": ["source-scan"],
      "acceptance_predicate": "A later reviewer can inspect the receipt."
    }
  ]
}
```

Допускаються тільки `read-only`, `reversible-local` і `owner-only`.
`allowed_paths` — відносні шляхи без `..`, абсолютних шляхів та Windows
separator. Залежності мають бути унікальними й утворювати DAG; результат не
залежить від порядку task у вхідному масиві.

`budget` має точні поля:

- `max_high_level_tasks`, `max_executor_tasks`, `max_dependencies_per_task`;
- `max_allowed_paths_per_task`, `max_static_tools_per_task`;
- `max_task_instruction_bytes`, `max_task_output_bytes`;
- `max_attempts_per_task`, `max_parallel_tasks`.

Усі мають жорсткі верхні межі. Якщо інструкція після декомпозиції або число
cards не вкладаються у budget, план відхиляється, а не обрізається мовчки.

## Декомпозиція та межі

`decompose_high_level_plan(...)` створює
`promin.weak-model-execution-plan.v1`, прив'язаний SHA-256 до нормалізованого
source plan. Для кожного не-owner task є рівно три послідовні cards:

1. `:preflight` — `static-tool-first`, тільки static tools і без мутації;
2. `:execute` — один обмежений виконавець у `allowed_paths`;
3. `:review` — перевірка лише прив'язаних receipts.

Кожний card має SHA-256 інструкції, ліміти output/attempts і явні залежності.
`UNAVAILABLE` tool може бути лише спостереженням у receipt; він не створює
credit, success чи приховане fallback-виконання.

`owner-only` не породжує executor або tool task. Замість цього створюється
`:owner-decision` зі статусом `OWNER_DECISION_REQUIRED`. Він є stop boundary:
ані модель, ані reviewer не можуть завершити його або замінити рішення owner.
Після окремого рішення owner потрібен новий авторизований план/route, а не
ручне переписування старого receipt.

У plan, кожному card, receipt, review та resume результаті незмінно:

```text
authority_effect=none
authority_granted=false
pass_credit=false
acceptance_pass=false
product_acceptance_pass=false
```

Отже completion картки означає тільки наявність структурно коректного
спостереження. Він не є доказом product/release acceptance і не наділяє
виконавця владою.

## Receipts, review і resume

`create_executor_receipt(...)` формує receipt з exact task digest,
instruction digest, плановим digest, номером спроби, output digest та
`output_bytes`. Значення `output_bytes` перевіряється проти card budget.
Actual output або його семантика не стають істинними лише через digest: це
завдання окремого evidence route.

`review_executor_receipts(...)` приймає лише хронологічну послідовність:

- спроби task мають бути без пропусків;
- task не стартує до завершення всіх залежностей;
- після `COMPLETED` або `OWNER_DECISION_REQUIRED` новий receipt відхиляється;
- лише `FAILED` / `BLOCKED` з невичерпаним budget може з'явитися у
  `resumable_task_ids`;
- owner-only переходить у `owner_decision_task_ids`, а не у виконавчу чергу.

`owner-decision` card взагалі не приймає executor receipt: такий запис не
може замінити окремий owner-authorized route.

`resume_execution_plan(...)` повертає тільки готові або безпечно поновлювані
ідентифікатори й digest review. Кількість одночасно запропонованих ID ніколи
не перевищує `max_parallel_tasks`; додаткові готові cards лишаються у
`deferred_task_ids`. Resume не виконує cards сам і не послаблює межі
owner/Core authorization.

## Не є доказом acceptance

Цей шар можна тестувати статично на будь-якій підтримуваній платформі. Таке
тестування підтверджує лише детермінізм, budget, DAG і fail-closed межі.
Реальна tool execution, host availability, content correctness, mutation,
інсталяція, runtime/visual/performance evidence та acceptance залишаються
`PENDING_RUNTIME_EVIDENCE` або іншими окремими gate, доки їх не доведено.
