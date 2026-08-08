# Чисте переініціалізування

## Призначення

Чисте переініціалізування — це окремий, явно руйнівний режим для заміни
активного control plane проєкту. Воно не є `repair`, не є guided-init і не
створює міст сумісності зі старим станом.

Режим допускається лише для exact digest-bound project package після явного
підтвердження власника. Його порядок незмінний:

```text
перевірити package і extension closure
→ перевірити exact intent та owner confirmation
→ заморозити авторитетних writer-ів
→ quarantine цілого старого .promin
→ standard init нового activation
→ overlay дозволених tracked extensions
→ import package-defined tasks нормативними mutation-ами
→ minimal postcheck
→ верифікувати й опублікувати результат
```

До публікації будь-яка помилка відновлює **цілий** quarantined `.promin`, або
залишає новий root неавторитетним. Після публікації rollback старого root
заборонений.

## Межа старого стану

Clean mode ніколи не переносить або не відтворює:

- projections, SQLite databases чи інші generated views;
- locks, leases, provider caches, receipts, evidence або журнали;
- старий operational progress, WorkCards чи product credit.

`CleanStateAdmission` фіксує це як `false`: state migration, replay previous
progress, acceptance, pass credit, product credit та authority. Отже сам факт
допуску або quarantine не є успішною ініціалізацією й не дає acceptance.

## Writer identity та liveness

Запис writer-а повинен містити не лише PID, а й process-birth token,
activation digest, intent digest і межі lease. Класифікатор має такі безпечні
результати:

| Стан | Наслідок для recovery |
| --- | --- |
| `ABSENT` | допускається, якщо зовнішній authoritive writer lock вже утримується |
| `INACTIVE` | допускається: PID не існує або PID було повторно використано іншим process instance |
| `LIVE` | блокує recovery |
| `LEASE_EXPIRED` | блокує recovery: process instance ще живий |
| `INDETERMINATE` | блокує recovery: відсутність спостереження не є доказом неактивності |

`promin.writer_identity` класифікує liveness, але не замінює авторитетний
filesystem writer lock. Інтегратор має утримувати цей lock від writer freeze
до publication або rollback.

На Windows process-birth token отримується через `GetProcessTimes`; на Linux —
через boot ID та start tick `/proc`. Якщо платформа не дає сильного birth
identity, результат навмисно `INDETERMINATE`, а не успішний recovery.

## Tracked extension boundary

`promin.recovery` приймає лише typed directory roots із file/byte budgets і
будує exact SHA-256 member closure до будь-якої мутації target control root.
Для control directory дозволений лише `.promin/docs/**`. Старий
`.promin/portable/**` не є alpha4 alias і не може бути внесений у typed
extension closure.

Під час admission заборонені `.promin/init`, `.promin/state`,
`.promin/providers`, `.promin/evidence`, `.promin/cache`, `.promin/locks`,
`.promin/leases`, `.promin/host`, `.promin/standard`, `.promin/generated`,
`.promin/recovery` і весь `.promin-host`. Links, junctions/reparse points та
hard-linked files не входять до closure. Перекриття root-ів, case collisions,
не-NFC names та перевищення budgets відхиляються.

Overlay виконується лише після byte-exact standard init. Цей документ і
admission helper не дозволяють копіювати tracked extensions із старого
operational root: перед quarantine будь-який selected extension source усередині
попереднього `.promin` відхиляється. Перед quarantine closure читається вдруге;
зміна хоча б одного selected byte після admission відхиляє операцію.

## Quarantine та rollback

Старий root переміщується як один directory object з
`.promin` у `.promin-host/recovery/<intent-digest>`. Destination має бути
відсутнім, знаходитись на тому самому filesystem і не може бути замінений.
Використовуються лише no-replace moves:

- Windows: `MoveFileExW` без `MOVEFILE_REPLACE_EXISTING`, із
  `MOVEFILE_WRITE_THROUGH`;
- Linux: `renameat2(RENAME_NOREPLACE)`;
- інша платформа: `UNAVAILABLE`, без небезпечного fallback на replace/merge.

Перед створенням host-local recovery parent перевіряються project path, тип
старого root, destination та writer liveness. Після цього root перечитується
перед no-replace move. Recovery ніколи не видаляє старий root як частину
rollback: воно або переміщує цілий root назад до порожнього `.promin`, або
fail-closed.

## Exact-intent reuse

Існуючий результат можна reuse лише якщо одночасно збігаються intent digest,
package digest і extension admission digest, а зовнішній activation/result
verifier повертає саме `True`. Інший intent відхиляється **до** запуску
verifier-а. Неперевірений, частковий або старий результат не є підставою для
reuse.

## Статус доказів цього шару

Цей шар є фундаментом протоколу, а не public acceptance claim. Він не запускає
standard init, task import, doctor, status, refresh або package publication.
Фокусні Windows-тести перевіряють actual full-root quarantine/rollback,
owner-intent binding, PID reuse/liveness і extension restrictions. Linux має
реалізацію no-replace move, але в цьому пакеті не отримує runtime pass credit
без окремого Linux host run. macOS не має реалізації no-replace move в цьому
шарі й чесно повертає `UNAVAILABLE`.
