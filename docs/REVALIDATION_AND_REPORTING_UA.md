# Heavy revalidation і підготовка звіту

`promin.revalidation` — це read-only orchestration для відновлення після
перерваної або сумнівної перевірки. Він не відновлює progress, не редагує
SQLite, проєкції, journal, receipts, locks, leases або evidence; також не
запускає provider, configure, build чи runtime. Реальні перевірки залишаються
в уже наявних authority-модулях і передаються тільки як явно оголошені
`ReadOnlyRevalidationCallback`.

## План і bounded фази

`RevalidationPlan` зв'язує:

- стабільний `plan_id`;
- canonical digest input identity;
- впорядкований список phase id;
- бюджет кожної фази та загальний бюджет;
- `restart_identity` і `plan_digest`.

Фаза отримує лише `RevalidationContext` з digest-ами: очікуваним input,
попереднім output, plan і restart identity. Вона не отримує writable project
object, шлях до control root, SQLite connection або projection. Callback має
повернути `RevalidationObservation` з observed input digest та canonical output
identity. Обов'язкова ознака callback — `read_only=True`; неявний callback або
неоголошений write route відхиляється до виконання фази.

Кількість фаз, час однієї фази, загальний час, identity payload і reason мають
обмеження. Перший `FAIL`, `UNAVAILABLE`, `STALE` або `CHANGED` зупиняє маршрут.
Якщо observed input digest відрізняється від очікуваного, результат примусово
має статус `CHANGED`, навіть якщо callback помилково повернув `PASS`.

## Restart-safe receipts і reconsolidation

Кожен `RevalidationCheckpoint` містить phase id, expected та observed input
digest, output identity/digest, виміряний elapsed time і non-promoting fields.
`RevalidationReceipt` серіалізується в canonical record з власним
`receipt_digest`. Його можна передати в наступний process як data; модуль не
пише цей record до проєкту самостійно.

`reconsolidate_revalidation(...)` приймає тільки receipts з точним
`plan_digest`, `input_digest`, `restart_identity` і phase sequence. Інший
receipt не використовується як checkpoint: він лишається в
`stale_receipt_digests`, а результат отримує `STALE`. Два receipts з одним
планом, але різними output identities на тому самому checkpoint, отримують
`CHANGED`. Це запобігає тихому продовженню з застарілою або конфліктною
історією.

`revalidate_recovery(...)` може зупинитися після `max_phases`; це створює
`PENDING` receipt для точного prefix. Під час повторного запуску виконуються
лише решта фаз, якщо попередній prefix і його chained digest-и збігаються.
Після terminal non-pass автоматичний retry не відбувається: потрібен новий
контекст або явне нове revalidation рішення.

## Підготовка звіту

`prepare_revalidation_report(...)` формує компактний data record лише з уже
наявного receipt. Він показує checkpoint-и, changed identities, stale receipt
digest-и, наступну фазу та zero-effect counters. Функція не публікує файл і не
перетворює derived report на authority.

Усі plan, checkpoint, receipt і report records незмінно містять:

- `acceptance_pass=false`;
- `product_acceptance_pass=false`;
- `pass_credit=false`.

`PASS` у revalidation означає лише завершення заявлених read-only authority
спостережень для точної identity. Це не є installability, runtime, visual,
performance або release acceptance.
