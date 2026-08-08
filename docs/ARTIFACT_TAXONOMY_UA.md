# Таксономія артефактів Promin

## Межа, що комітиться

Єдина стандартна межа переносимих control-документів — `.promin/docs/**`.
Вона містить лише короткі нормативні документи та поточні компактні підсумки.
Кожен файл має бути звичайним файлом без symlink/reparse point, мати
канонічний NFC-шлях і пройти byte/file-count/report/total бюджет до
публікації. Невідомий клас, detail-артефакт або перевищення бюджету
блокує публікацію; Promin не видаляє докази, щоб зробити результат зеленим.

Типові extension-поверхні розташовані лише під
`.promin/docs/extensions/<id>/**`. Їхній тип, корінь, файли, bytes і SHA-256
мають бути явно зв'язані project-package manifest-ом. Extension не може
містити `init`, `state`, `providers`, `evidence`, `cache`, `locks` або
`leases` і накладається тільки після створення нового Activation.

## Класи та публікація

| Клас | Де існує | Звичайний режим | Credit |
|---|---|---|---|
| `portable-normative-doc` | `.promin/docs` | `minimal` | ні |
| `compact-current-report` | `.promin/docs` | `minimal` | ні |
| `diagnostic-inventory` | `builds/analysis` | явний `diagnostic` | ні |
| `forensic-log` | `.promin/logs` | явний `forensic` | ні |
| `runtime-evidence` | `.promin/evidence` | окремий gate | лише predicate gate |
| `cache` | `.promin/cache` | host-local | ні |
| `recovery-backup` | `.promin/recovery` | host-local | ні |

`minimal` не створює inventory, raw scanner output, HTML/XML, повні receipts,
process transcript або historical report. `diagnostic` і `forensic` не роблять
такий вихід tracked: їх треба утримувати та прибирати за host-local retention
policy. У tracked документації зберігається один current compact registry і
summary; superseded/history payload залишається host-local.

## Командний seed

`team-seed.json` — неавторитетний переносимий seed. У ньому є intent,
profile та repository digest, але немає WorkCard, Task, Finding, Candidate,
Grant, Lease, event, projection, SQLite, receipt чи host path. Отримувач
спочатку створює і верифікує Activation, а вже потім породжує першу WorkCard
нормативною операцією. Seed не надає authority, acceptance або pass credit.

## Класифікація архіву

Класифікація залежить від оголошеної control-межі, а не від окремого слова в
імені файлу. Наприклад, `Evidence`, `History` чи `Providers` у product-source
шляху не є operational state. Лише явний `.promin/<operational-root>` або
оголошений клас визначає exclusion із cloneable package.

## Документаційна якість

Компактний contract catalogue пріоритизує fan-in, ownership, lifetime,
transaction, failure і configuration boundary. Meaningful contract описує
purpose та релевантні ownership/lifetime/failure/configuration умови.
Порожній коментар, коментар лише з назвою файлу, generated boilerplate або
наявність host-local HTML/XML не дають documentation credit. Докладний
Doxygen/XML або еквівалентний вивід належить host-local diagnostic contour.
