# Статичний admission і dynamic handoff

`promin.static_admission.run_static_admission()` — це обмежена локальна
перевірка джерельного дерева. Її `PASS` означає лише цілісність перевіреної
статичної межі; він не є доказом компіляції, запуску, installability, якості
продукту чи готовності до релізу.

## Межа статичного виконання

Перевірка читає лише метадані файлового дерева та опис pending handoff. Вона
не викликає provider, не конфігурує і не збирає проєкт, не запускає runtime і
не відкриває SQLite. У кожному результаті лічильники цих ефектів дорівнюють
нулю, а `compiler_validated`, `runtime_validated`, `acceptance_pass`,
`product_acceptance_pass`, `release_eligible` і `pass_credit` залишаються
`false`.

Порядок дешевих перевірок незмінний:

1. `source` — обмежений обхід regular source tree без переходу через symlink
   або reparse point;
2. `documentation` — `.promin/docs` існує як реальна непорожня папка і не
   містить operational payload (provider/cache/state/lock/SQLite);
3. `portability` — немає link/reparse меж і імен, непридатних для Windows;
4. `handoff` — передано точний контракт подальшої dynamic-перевірки.

Обхід має фіксовані бюджети кількості entries і байтів. Перевищення бюджету,
недоступне дерево, special file, symlink або reparse point — `FAIL`, а не
неявний пропуск. Відсутній handoff дає `SKIPPED`, отже загальний статус не
може бути `PASS`.

## Контракт dynamic handoff

`promin.dynamic_handoff.validate_dynamic_handoff()` приймає лише точний набір
полів: `id`, `status`, `allowed_write_scope`, `forbidden`,
`required_evidence`, `acceptance_predicate`, `invalidation_class` і
`stop_conditions`. Статус може бути лише `PENDING_DYNAMIC`; поля, що могли б
імітувати promotion, не допускаються.

`dynamic_handoff_receipt()` має детерміністичний digest контракту, але також
завжди повертає `promotion_allowed=false`, `acceptance_pass=false`,
`product_acceptance_pass=false` і `pass_credit=false`. Реальна dynamic route
повинна окремо зібрати bound evidence та перевірити свій predicate.

## Selector shards

`promin.selector_shards` створює детерміністичний manifest: об’єднання
selectors кожного shard має точно збігатися з повним selector set, без
duplicate або extra selector. Для всіх shard фіксуються однакові
`timeout_seconds` і `memory_bytes`; marker expression (за замовчуванням
`not scale`) входить у `selector_digest`.

Loader строго парсить JSON, відхиляє duplicate JSON keys і нормалізує/
перевіряє digest. Runner перед запуском повторно валідовує manifest і не може
підмінити selectors, marker або limits. Якщо host не вміє примусово встановити
memory limit, він повертає `UNAVAILABLE`, не `PASS`. Aggregate timeout та
відсутній terminal receipt не є semantic PASS і ніколи не дають credit.
