# Product inspection — статичне, обмежене спостереження

`promin.product_inspection` дає API для детермінованого огляду довільного
product tree. Це не CLI, не configure/build/runtime route і не producer
evidence. Модуль лише читає metadata та обмежені UTF-8 файли, не відкриває
SQLite, не викликає provider/tool і не записує жодного артефакту.

## API

```python
from promin.product_inspection import inspect_product, serialize_product_inspection

report = inspect_product(product_root, profile=project_override, limits=limits)
machine_json = serialize_product_inspection(report, audience="machine")
client_json = serialize_product_inspection(report, audience="client")
```

`profile` може бути `ProductInspectionProfile` або точним mapping з полями:

- `profile_id` — generic lowercase identifier;
- `source_extensions`;
- `documentation_extensions` і `documentation_directories`;
- `tool_markers` — generic tool profile → safe relative marker paths;
- `recovery_markers` — safe relative declarations recovery contour.

Профіль не містить project ID, абсолютних шляхів або припущень про конкретний
продукт. Caller може вибрати, відхилити або замінити його project/user override
перед викликом API. Невідомий ключ, unsafe path, duplicate або непідтримуваний
suffix є помилкою виклику, а не тихим fallback.

## Межі та мінімальність

За замовчуванням обхід bounded: 20 000 entries, 512 MiB загального metadata
обсягу, 4 MiB для одного читаного файла, 32 hotspots і 32 risk samples.
`InspectionLimits` дозволяє звузити або явно розширити ці межі. Перевищення,
unreadable entry, link/reparse point або special file робить результат
`PARTIAL`; це не маскується як нормальний результат.

Модуль не створює per-file inventory, raw log, cache або report на диску.
Навіть machine JSON існує лише в пам'яті caller-а. Якщо caller хоче зберегти
diagnostic inventory, він має окремо обрати host-local diagnostic/forensic
policy. Сам факт такого inventory не дає credit.

Адміністративні VCS roots (`.git`, `.hg`, `.svn`) не належать product payload і
не входять до tree digest. Інші каталоги, зокрема dependency або generated
content, не ховаються: вони або спостерігаються, або одержують explicit
bounded/partial сигнал.

Окремо exact host-transient names `__pycache__`, `.pytest_cache`,
`.mypy_cache`, `.ruff_cache`, `.coverage` та `htmlcov` не є product payload.
Вони не потрапляють у file inventory, hotspots чи static-risk samples, але
`inventory.excluded_host_transient` завжди показує їхні entry/file/directory/
byte counters, unavailable/special counters і reason breakdown. Це не є
приховуванням довільних даних: каталог `cache`, у тому числі
`product/cache/**`, не має special status і повністю інспектується.

## Machine surface

`report["machine"]` містить лише відносні NFC paths, metadata та digest-и;
вміст файла, абсолютний root, environment variables і OS error text не
виводяться. Surface охоплює:

- `inventory`: file/directory counts, bytes, extension counts і tree digest,
  якщо весь permitted tree прочитано;
- `architecture`: source extension counts, lexical dependency candidates та
  minimality facts (empty/duplicate content);
- `documentation` і `tool_profiles`: profile-driven declarations, де
  `DECLARED`, `UNAVAILABLE` або `PARTIAL` не є pass state;
- `recovery_capability`: лише marker observation; recovery не запускається і
  `recovery_verified` завжди `false`. Default generic Promin contour спостерігає
  `.promin/docs`, `.promin-host/recovery`, `promin/recovery.py` і
  `promin/revalidation.py`; наявність будь-якого marker-а означає лише
  `DECLARED`, а не verified recovery;
- `static_risk`: static REVIEW signals (binary, risky suffix, sensitive name,
  link/reparse, unreadable або budget issue);
- `hotspots`: bounded size + lexical branch-signal priorities, також
  `REVIEW_ONLY`;
- `evidence_confidence`: bounded-static або limited evidence та явні
  limitations.

Lexical dependency/complexity signals не є compiler, ownership, semantic або
runtime proof. Вони допомагають пріоритизувати наступний незалежний аналіз, а
не визначають architecture defect автоматично.

## Client surface

`serialize_product_inspection(..., audience="client")` повертає короткий
`ProductInspectionClientSummary`: counts, status, risk-code counts, declared
tool/recovery/doc status і evidence limitations. У ньому немає sample paths,
absolute root або content. Це призначено для безпечного UI/handoff summary.

Обидві JSON serialization canonical: sorted keys, compact separators, UTF-8
without implicit filesystem paths і завершальний newline. За незмінного tree,
profile та limits результат byte-stable.

## Жодного promotion

Кожен report фіксує:

```json
{
  "acceptance_pass": false,
  "pass_credit": false,
  "product_acceptance_pass": false,
  "release_eligible": false,
  "runtime_validated": false
}
```

`COMPLETE` означає лише, що статичне спостереження завершилося в обраних
межах. Воно не доводить build, installability, recovery replay, runtime,
visual quality, product acceptance або release readiness. `UNAVAILABLE` не
перетворюється на PASS, а `PARTIAL` завжди лишається partial.
