# Міграція з alpha.3 до alpha.4

Alpha.4 не переносить керівний стан alpha.3 «на місці». Перехід — це явне
чисте перевідкриття проєкту з перевіреного project package після підтвердження
власника. До підтвердження старий корінь не змінюють; після підтвердження його
ізолюють поза новим control root і створюють новий стан alpha.4.

Не переносяться і не відтворюються події, прогрес, проєкції, SQLite-бази,
provider cache, receipts, evidence, locks, leases, cache або будь-який інший
операційний вміст `.promin`. Для alpha.4 обидва твердження є незмінними:
`state_migration_supported=false` і
`previous_progress_replay_supported=false`.

## Що дозволено перенести

Project package є канонічною парою записів `project-package.json` і
`project-package-content.json` та деревом `seeds/`. Перший запис має точну
схему `promin.project-package.v1`. Другий зв'язує кожен seed з відносним
джерелом, ціллю, класом, розміром, SHA-256, mode і digest усього дерева.
Обидва записи мають бути canonical JSON; будь-який зайвий файл, symbolic link,
reparse point, неврахований seed або розбіжність bytes/digest є помилкою.

Єдиний tracked control root — `.promin/docs`. Звичайні portable-документи
можуть потрапляти лише до `.promin/docs/**`. Типізовані розширення можуть
потрапляти лише до `.promin/docs/extensions/<id>/**`; окремий
`.promin/extensions` не є допустимим root. Host integration і profile default
є деклараціями пакета, а не дозволом перенести попередній operational state.

## Чисте перевідкриття

Операція clean reinitialization має бути окремо підтверджена власником і
виконувати таку послідовність:

1. Перевірити project package до будь-якого запису в цільовий проєкт.
2. Ізолювати попередні active operational roots поза новим control root.
3. Створити мінімальний alpha.4 control state з канонічних Standard surfaces.
4. Overlay лише digest-bound members з `seeds/` у дозволені tracked targets.
5. Імпортувати нормативні задачі через звичайні mutation routes.
6. Перевірити clean state та перший package-defined WorkCard у межах обраного
   bounded postcheck profile.

`minimal` postcheck обмежується clean validation і першим WorkCard. Важкі
doctor/status/portability фази не можуть затримувати результат minimal init і
не можуть надавати acceptance credit самі по собі.

## Відкат і повторна активація

Повернення до alpha.3 можливе лише до публікації нового alpha.4 state: новий
root прибирають як один ізольований результат, а весь попередній root
відновлюють як ціле. Часткове копіювання баз, проєкцій або cache між версіями
заборонене. Після публікації потрібна окрема owner-директива, а не прихований
compatibility bridge.

## Кандидатний пакет

Final admission працює тільки з явним sorted tracked-file manifest. Вона читає
source root, класифікує відомий operational/generated вміст у точний delete
manifest, а незадекларований звичайний файл відхиляє. Дві незалежні зовнішні
клони створюють архіви з фіксованим порядком, bytes, SHA-256, canonical modes і
tree digest. Source root не змінюється.

Результат admission має статус `candidate`. Навіть за byte-identical A/B
архівів він завжди містить `acceptance_pass=false` і `pass_credit=false`.
Installability, runtime, visual або release acceptance потребують окремого
свіжого доказу.
