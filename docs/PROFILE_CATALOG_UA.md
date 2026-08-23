# Каталог profiles

Promin використовує revisioned `ResolvedProfile`, а не одну жорстко задану
назву. Композиція має детермінований порядок:

```text
explicit user requirements
→ project-local rules
→ detected technology facts
→ domain/workflow/platform layers
→ autonomy/language layers
→ generic language capability
→ safe reversible defaults
```

Bundled layers охоплюють general, C-family, web, Android, mobile, Windows,
recovery, autonomy та reporting-language contours. Project package може додати
default, але не може перевищити authority ceiling або підмінити explicit user
choice.

## Generic language catalog

`promin/language_catalog.py` є єдиним source of truth для мов, profiles і tools.
Він завантажує точну deterministic closure із семи bundled JSON profiles:

- `c-family-semantic` — C і C++;
- `csharp-semantic` — C#;
- `jvm-semantic` — Java, Kotlin, Scala і Groovy;
- `javascript-typescript-semantic` — JavaScript і TypeScript;
- `python-semantic` — Python;
- `open-source-tooling` — build, documentation і static-analysis contours;
- `weak-host-fallback` — portable contour для обмеженого host.

Loader зв’язує filename, `profileId`, family і language set. Missing, duplicate,
extra або misbound profile відхиляється; input order не впливає на canonical
result. Directory members, profile bytes, requested languages, availability
records і override layers мають ordinary count/byte bounds, тому каталог не
перетворює необмежений input на приховану роботу.

Public family IDs `java` і `javascript`, aliases та default extensions
залишаються сумісними. TypeScript, Kotlin, Scala та Groovy доступні expert init
через той самий каталог. `init_profiles.py` лише споживає нормалізовану
композицію і не має другого language registry. Усі profiles зберігають
product/release claims `false`.

## Open-source tool contours

Мовні profiles називають конкретні OSS-рішення:

- C/C++: compiler/build contours, Doxygen і static analysis;
- C#: `dotnet-compiler`, `roslyn-analyzers`, `docfx`;
- JVM: `javac`, `checkstyle`, `spotbugs`, `javadoc`;
- JavaScript/TypeScript: `eslint`, `typescript-compiler`, optional `typedoc`;
- Python: `python-syntax-check`, `ruff`, `mypy`, `sphinx`.

Це capability declarations, а не інсталяційний скрипт. Profile не доводить
наявність executable і не створює PASS. Реальний host observation належить
окремому gate receipt зі статусом `AVAILABLE`, `PASS`, `UNAVAILABLE`, `FAIL` або
`SKIPPED`; лише конкретний gate може інтерпретувати цей status у своєму вузькому
контексті.

## Складність і мінімальність

Profiles не обмежують складність проєктів або tasks. Вони задають семантичні
capabilities, статичні tools, documentation surfaces та budgets, які orchestration
використовує для довільного high-level DAG. Мінімальний init включає тільки
profiles, підтримані реальними facts; expert init може явно налаштувати повну
композицію.

Promin відповідає за deterministic profile resolution і bounded parsing. Права
доступу, process isolation та OS policy належать host/user environment.

## Поточне evidence

Combined expert-init/language slice: `64 passed, 1 deselected`. Це
source-level correctness evidence для одного `expert-init.json`, exact
seven-profile closure та спільного language catalog. Поточний hash ще не має
завершеного modeled Linux/WSL aggregate, тому Windows/Linux product acceptance
не заявляється.

```text
acceptance_pass=false
performance_acceptance=false
pass_credit=false
```
