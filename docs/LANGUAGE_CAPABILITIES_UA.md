# Каталог мовних можливостей

`promin.language_catalog` читає bounded JSON-каталог із
`language_profiles/` і детерміністично складає лише декларативний contour для
обраних мов. Це не probe компілятора, language server або документаційного
генератора: модуль не запускає процеси, не конфігурує build, не пише стан і не
надає authority чи acceptance credit.

## Підтримані family та вибір

Основні family — C-family (`c`, `cpp`, aliases `c++`), C# (`csharp`, `c#`),
Java/JVM (`java`), JavaScript/TypeScript (`javascript`, `typescript`, aliases
`js`, `ts`) і Python (`python`, `py`). Вибір не має fallback на назву
репозиторію: якщо для запитаної canonical мови немає profile, результат має
`status=UNAVAILABLE`, `unresolved_languages` і всі credit/acceptance поля
залишаються `false`.

Профіль може бути повним semantic profile v1 або компактним profile v1. В
обох випадках обов’язкові schema, `profileId`, `languages`, documentation,
verification та artifact policy; компактний варіант також задає
`sourceExtensions`. `staticCapabilities` є bounded доповненням до
`verification.cheapRequired`. Невідоме поле, duplicate key, symlink/reparse
point, неканонічна мова, двозначний owner мови, надвеликий файл/каталог або
true claim відхиляються fail-closed.

## Складений contour

`compose_language_capabilities()` повертає окремо:

- `selected_static_capabilities` — обов’язкові декларативні статичні checks;
- `selected_documentation` — primary/optional documentation capabilities;
- `selected_tools` — recommended або явно custom tooling;
- `availability_results` — тільки спостережені/не спостережені статуси;
- `profile_selections` та artifact policies з profile provenance.

За замовчуванням `documentation.userChoice=ask` нічого не вибирає. Для кожного
обраного profile override має точну форму `documentation` і/або `tools` з
`mode` (`accept`, `decline`, `custom`) та `items`. `custom` може вибирати лише
вже задекларовані primary/optional або recommended/optional можливості. Він не
може додати tool, мову, статичну можливість, artifact root, claims або змінити
identity профілю.

## Availability та digest

Availability передається caller-ом як `{status, detail}` для вже відомої
capability. Допустимі стани: `AVAILABLE`, `UNAVAILABLE`, `FAIL`, `SKIPPED`.
`PASS` навмисно не допускається: static composition не виконує tool і не може
видати runtime/build proof. Відсутнє спостереження повертається як
`SKIPPED/not-observed`; відсутня required static capability визначає загальний
`SKIPPED`, а не успіх.

Кожен профіль має `source_digest` (точні прочитані bytes) і `profile_digest`
(NFC-normalized canonical JSON). `catalog_digest` зв’язує profile identity та
canonical digest; `composition_digest` зв’язує catalog, language selection,
profile selections, relevant availability results та всі false claims. Тому
зміна override або релевантного host observation змінює digest, але не може
підвищити `acceptance_pass`, `pass_credit`,
`product_acceptance_pass` чи `release_approved`.

## Публічний CLI tooling

```text
promin tooling plan --language LANGUAGE --tool DECLARED_TOOL --action ACTION [--argument RELATIVE]
promin tooling probe --language LANGUAGE --tool DECLARED_TOOL --action ACTION [--executable PATH] [--timeout-seconds N]
promin tooling run --language LANGUAGE --tool DECLARED_TOOL --action ACTION [--argument RELATIVE] [--output-root RELATIVE] [--executable PATH] [--timeout-seconds N]
```

Мовні aliases (`c`, `cpp`, `c++`, `c#`, `jvm`, `kotlin`, `scala`, `groovy`)
нормалізуються до canonical language IDs bundled profile. Натомість `--tool`
і capability IDs приймаються лише як точні declaration IDs. Немає raw `argv`,
installation/network switch або implicit tool selection. `--executable` —
explicit canonical local path, що перевіряється проти declaration mapping. Усі
маршрути діагностичні, без telemetry, acceptance, pass-credit або release claims.

`plan` і `probe` є diagnostic routes. `run` також лишається diagnostic: на цьому
Windows host він може повернути `UNAVAILABLE_HOST_PATH_GUARD`, що означає
недоступність безпечного host path guard, а не успішний запуск tool і не
platform acceptance.
