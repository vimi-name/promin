# Відновлення, ревалідація, реконсолідація і звіт

Promin розділяє planning, execution та evidence. Revalidation не переписує
історію і не підвищує claims лише тому, що operation завершилася. Кожний
результат прив’язаний до plan, input, configuration та попередніх receipts.

## Строгий п’ятифазний цикл

`promin.revalidation_workflow` виконує один обов’язковий порядок:

```text
INSPECT → REPAIR → REVALIDATE → RECONSOLIDATE → REPORT
```

Фази мають вузькі ролі:

- `inspect` — визначити поточний стан і required phases без виконання;
- `repair` — виконати bounded clean reinitialization за вже підготовленим
  admission;
- `revalidate` — виконати заявлені read-only phases;
- `reconsolidate` — відновити єдиний status із наявної послідовності receipts;
- `report` — підготувати non-authoritative reporting record.

`plan_revalidation_workflow(...)` повертає canonical no-write plan.
`execute_revalidation_workflow(...)` виконує рівно поточну фазу і створює один
create-only receipt. Пізню фазу не можна запустити окремо або перестрибнути
через попередню. Retry дозволений лише для тієї самої фази з точним predecessor
receipt і наступним ordinal; перехід уперед дозволений лише до безпосередньо
наступної фази. Немає прихованого tool discovery або автоматичного розширення
scope.

## Детермінований control flow

`RevalidationWorkflowPlan` зв’язує:

- semantic workflow identity, mode і semantic subject digest;
- implementation та configuration digests;
- retry ordinal;
- predecessor receipt для retry/resume;
- required phases і prior receipt digests;
- mode-specific inputs.

Semantic identity є path-independent: її визначають logical workflow,
authority/configuration identity, початковий semantic subject і точна phase
sequence, а не абсолютний project або receipt path. Тому однаковий workflow у
різних коренях має однакову semantic identity. Водночас кожний runtime plan і
receipt явно зв’язує конкретні шляхи, з яких реально читалися inputs та куди
писалося evidence.

Перший `inspect` attempt не має predecessor. Кожний наступний attempt або фаза
посилається на точний попередній receipt. Це робить pause, resume, retry та
audit відтворюваними: state визначається records, а не пам’яттю агента.

Revalidation phases мають детермінований порядок. `PENDING` означає, що частина
required phases ще не виконана; `CHANGED`, `UNAVAILABLE`, `FAIL` і `PASS`
зберігають вузьку domain-семантику. Caller-recorded PASS не приймається як
авторитетний результат без виконання відповідного route.

## Керована складність

Resource bounds є частиною plan, а не прихованою евристикою:

- не більше 16 prior receipts;
- не більше 16 retry attempts;
- workflow receipt не більше 4 MiB;
- phase count і execution limit задаються явно;
- clean recovery має окремий bounded attempt count.

Перевищення limit повертає typed failure або pending state. Воно не обрізається
до фальшивого PASS.

## Recovery і reporting

Repair використовує існуючі domain primitives clean reinitialization. Він не
імпортує попередній operational state і не видає product credit. Reconsolidation
перевіряє повноту, predecessor chain і порядок prior receipts. Reporting
приймає лише завершений reconsolidation predecessor, серіалізує вже відомий
стан і не змінює його.

Receipt містить plan, authority/config identity, subject, predecessor, ordinal,
execution state, result kind, result digest і власний receipt digest. Failure
також записується як non-promoting record, тому interrupted або невдалий run
можна перевірити й свідомо відновити.

## CLI

Revalidation залишається вкладеною в наявну surface:

```text
promin doctor --revalidate INPUT [--execute-revalidation]
```

Без execute flag команда лише готує plan. Поточний frozen CLI count
`58 passed` належить weak lifecycle + focused weak CLI slice і не переноситься
як окремий числовий доказ цього `doctor` boundary.

## Межа відповідальності

Promin відповідає за deterministic plans, IDs, ordering, state, budgets і
receipts. OS permissions, process isolation, backup policy та довіра до
локальних executors належать host/user environment.

## Поточне evidence

Focused strict-cycle revalidation slice: `39 passed`. Це source correctness, не
runtime або product acceptance; weak-related CLI evidence обліковується окремо.

```text
acceptance_pass=false
product_acceptance_pass=false
performance_acceptance=false
pass_credit=false
```
