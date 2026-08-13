# Alpha.4 — heavy hardening wave

## Активний обсяг

Версія лишається `1.0.0-alpha.4`. Хвиля посилює великий physical workload, storage/recovery, мінімальний та експертний init, мовні профілі, слабкі локальні моделі, product inspection і порівняльний benchmark harness.

Mrets-шар збережено. UGT-шар є додатковим. Proxy/stub acceptance не використовується.

## Реалізований зріз

- Core batch ceiling піднято до 128 подій, щоб один Task і 127 Relations були одним атомарним batch.
- State-binding index зберігає лише канонічні byte-boundary вузли, зберігаючи точний `typed-sparse-merkle-v1` root.
- Runtime checkpoint перенесено на нормалізовані bounded rows; aggregate digest обчислюється потоково без 16 MiB моноліту.
- Windows event history має фізичні immutable handles, точну closure-перевірку та явний fallback при capacity exhaustion.
- Усі post-HEAD non-authoritative finalization failures (derived indexes, checkpoint, Windows control і pending cleanup) відокремлені від authoritative commit outcome; authority перевіряється повторно, а часткова derived-generation інвалідовується.
- Init має мінімальний і експертний режими, generic language profiles, recovery/revalidation та weak-model execution decomposition.
- Saturation route має storage preflight, 8 GiB fail-safe headroom, growth model, telemetry, окремі storage/generic terminal receipts і create-only publication для failure evidence.

## Свіжа діагностична перевірка

- Derived storage: `9 passed`.
- Authority/Domain checkpoint: `4 passed`.
- Init/languages/weak-model: `34 passed`.
- Recovery/revalidation/publication: `48 passed, 1 skipped`.
- Provider/receipts/adversarial: `31 passed, 1 skipped`.
- Product inspection/minimality/comparison/Linux-model tests: `22 passed`.
- Windows EventStore persistence aggregate до останнього розширення: `88 passed, 1 skipped, 31 subtests passed`; після нього незалежний post-HEAD/batching/state-binding rerun: `14 passed`.
- Search-scale non-scale: `23 passed, 1 deselected, 29 subtests passed` на стабільному implementation closure.
- Exact package tree після repair refresh: 231 файл / 17 каталогів; 229 manifest payload hashes і 230 checksum entries перевірено незалежно. `verify-tree` валідний, версія лишилась `1.0.0-alpha.4`, Core bundle digest — `1dc3a1a34c7c60557028c5eeeac0d7f4d64625d8c2445bac782a56e51fa8858f`.

Пропуски не мають pass-credit. CodeRabbit review був недоступний через відсутню інтерактивну автентифікацію; ручний висновок не підміняє його.

## Виявлена зовнішня причина storage failure

WPR залишив два ETL payload загальним обсягом `212155236352` bytes (`197.585 GiB`). Вони були у 507 разів більші за failed Promin tree. WPR зупинено, stale test/workspace roots очищено. Це пояснює конкретний `SQLITE_FULL`, але не скасовує окремі intrinsic scale fixes вище.

## R4 100k — відхилення оракула, не projection

Exact r4 candidate `f46595c48b56417b5c19c1b5cc000420cfb97b3863d195fd326efbc0c0f3f291` виконав незменшене створення corpus і projection у `D:\ProminValidation\alpha4-r4-100k-f46595c4-20260811T121141Z`. Durable projection містить `100000 Artifact + 1599 Task + 4 Grant + 1 Candidate = 101604` entities, `198999` Relations; EventStore HEAD має sequence `1604`.

Run був правильно відхилений старим harness-оракулом, який очікував `101603`, а наступний predicate очікував би `1602`. Це не performance/acceptance pass. Виправлено всі producer/Schema/evidence/audit/conformance consumers: exact type contour, `entity_count=101604`, `relation_count=198999`, semantic commits `1604`. Scale-тест читає commit count із SHA/size-bound `raw/operation-metrics.json`, а не з неіснуючого top-level поля.

Non-storage відмова після preflight тепер залишає sealed `saturation-failure.json` з усіма claim-полями `false`. Late storage breach лишається `SaturationStorageFailure`; підміна output path до failure publication не дозволяє unlink/overwrite у replacement directory. Receipt чесно фіксує лише `workspace.exists` і `preservation_verified=false`.

Свіжа інтегрована перевірка цього repair-зрізу: `48 passed, 1 skipped, 25 subtests passed`; після package refresh окремий semantic-corpus route пройшов: `1 passed in 184.19s`; `compile_schema.py --check` і self-check пройшли. Full 100k після repair ще не запускався, тому `acceptance_pass=false`, `performance_acceptance=false`, `pass_credit=false`.

## Відкладені докази

- свіжий exact same-version candidate ZIP;
- незменшений Windows 100000-file / 600-query run;
- два незалежні Windows non-scale layouts;
- modeled Linux validation у WSL/Docker;
- повний Promin vs Markdown vs empty benchmark;
- deterministic product-inspection receipts;
- короткий клієнтський PDF із зовнішніми receipt bindings.

## R5 100k — повний corpus/projection і чесний tail-blocker

Exact same-version candidate `1149430402e1a12779f855ae7fb49b1c7363dfe25357b461ce1dabe45dd121d8`
двічі пройшов повне semantic ingestion: `1604` batches / `200603` events. Перший
foreground run завершив ingestion без projection і має окреме create-only interruption
observation. Другий detached run побудував projection з точним контуром
`100000 Artifact + 1 Candidate + 4 Grant + 1599 Task = 101604` та `198999`
Relations, після чого був відхилений query harness із
`continuation v2 omitted fields: ['grant_claim_digest']`. Це не product/storage failure:
публічний RetrievalPage навмисно приховує Grant claim усередині authenticated
`resume_binding` і відкриває лише `resume_binding_digest`.

Repair зберігає цю межу: `ProminService.search(..., continuation_token=...)` повторно
авторизує subject/Grant, перевіряє current projection/head і передає точні
query/depth/budget/ranking/TTL bindings до Projection. Старий `continue_search`
залишається лише для `ReadyFrontier`. Saturation harness перевіряє точний публічний
13-field envelope, стабільний `resume_binding_digest`, суворо зростаючий cursor і
продовжує retrieval через публічний service search. Підміна Grant/subject/query/budget,
пошкодження token і пряме використання retrieval token як ReadyFrontier fail closed.

## Performance hardening після R5

Версія лишається `1.0.0-alpha.4`. Цей зріз не змінює workload і не отримує
performance/product pass-credit до нового повного 100k запуску.

- State-binding v3 тепер читає union усіх зачеплених byte-boundary paths одним
  recursive SQLite SELECT замість 33 послідовних SELECT. Для однакового 128-Relation
  batch точний root і 4069 node writes лишилися byte-identical; 30 чергованих
  вимірювань дали 153.661 ms → 134.951 ms для staging. SQLite `auto_vacuum=FULL`
  прибирає накопичення freelist, а recovery зберігає лише одну активну disposable
  index/authority generation. Інтегрований storage/batching зріз: `12 passed`.
- Windows physical history seal зберігає повний byte-verification під час admission
  і точну O(N) directory-closure/witness перевірку кожного healthy commit. Replay
  lookup за sequence тепер використовує побудований лише з уже утримуваних шляхів
  індекс: для 1604 journal/authority pairs старий контур мав 5,145,632 переглядів
  членів, а індексований — 3,208, не послаблюючи missing/ambiguous rejection.
  Кожний immutable файл і надалі має власний no-write/no-delete handle; це свідома
  ціна точного physical seal, а не прихована performance-перемога.
- Projection rebuild використовує bounded bulk staging і створює search indexes
  після bulk writes. На counterbalanced 10240 Artifact + 10240 Relation contour
  median wall time зменшився 9.167202 s → 6.413626 s, SQLite execute calls
  72624 → 1153. Reference і bulk outputs збігаються для entities, Relations,
  semantic rows/root, operational order та FTS, включно з repeated entity update
  і Task transition. Це microbenchmark, не 100k acceptance.
- Query-tail regression через публічний `ProminService.search` охоплює 2048
  inventory Artifact, 127 READS, 12 DEPENDS_ON, depths 1..12, 13-page exact
  continuation union та незменшений детермінований 600-query plan. Він завершився
  за 92.14 s; wrong Grant/subject/TTL/ranking/depth/budget, token tamper, expiry і
  stale HEAD fail closed. Порожній legit miss тепер має schema-valid
  `effective_top_k=0`; негативні, boolean і значення понад top-k ceiling відхиляються.
- Додано claim-free checkpoint/projection профайлери та SHA-bound performance model.
  Модель бере SQL geometry з поточного `events.py`: 2 binding SELECT + 1 union SELECT
  на commit, тобто 4812 для 1604-commit 100k contour; усі prediction/claim/
  acceptance поля залишаються false.

Три широкі експериментальні зрізи навмисно не залишені в продукті. Incremental
runtime-checkpoint chain відхилено після recovery P1 на base-only → first-delta;
весь `service.py` lane, два тести й невикористаний API відкочено. Розширений
phase-timing lane також відкочено: незалежний review виявив неповну validator binding,
неправдиву назву RSS peak і неоднозначні aggregate elapsed boundaries. Windows
`ReadDirectoryChangesW` fast path відкочено після повторних native OVERLAPPED-lifetime
P2: у продукті не залишено notification, retention або handle-cap механізмів.
Це зберігає
правило мінімальності: у канонічному дереві немає напівперевірених механізмів.

Поточний full-checkpoint write amplification лишається відомим performance debt.
Новий повний Windows 100k запуск має окремо довести ingestion, два rebuild,
600-query tail, storage і RSS на exact same-version candidate. До цього:
`performance_acceptance=false`, `acceptance_pass=false`, `pass_credit=false`.

Окремо завершений run із перевищеним performance profile тепер проходить повну
структурну/криптографічну перевірку з `require_pass=false` і публікує sealed
`saturation-result.json` зі `status=fail`; це не надає acceptance або pass-credit.
Malformed fail-result не публікується.

Дві виміряні ingestion тривалості — `113m21s` і `115m02s`; це значно вище
канонічного `600s` ceiling. Retained semantic state перед projection був близько
`965 MB`, projection SQLite — `378454016` bytes, а sampled working set перевищив
`1.1 GB`. Ці дані є діагностичними: вони підтверджують scale-capacity, але прямо
спростовують поточний performance/low-memory acceptance. Fresh repaired candidate,
повний query tail і подальша performance-хвиля залишаються обов'язковими.

Фінальна інтеграційна перевірка цього зрізу виконана з вимкненими bytecode/cache:

- state-binding/storage/batching: `12 passed`;
- Windows exact seal/history/prefix: `21 passed, 1 skipped, 10 subtests`;
- projection durability + projection suite + public continuation: `51 passed, 4 subtests`;
- query-tail route після package refresh: `1 passed in 87.95s`;
- claim-free profiler/model suites: `19 passed`;
- schema boundary: `2 passed, 3 subtests`, `compile_schema.py --check` — pass;
- saturation self-check — pass, але `full_100k_executed=false`;
- canonical package closure: 244 files, 242 payload files, 243 checksum entries;
  `verify-tree --install-mode current-environment` — valid, version лишилась
  `1.0.0-alpha.4` / `1.0.0a4`.

Повний non-scale aggregate у цій хвилі не запускався: застосовано цільовий Tier A,
а новий exact 100k та дворазові Windows/Linux aggregates залишаються наступним
evidence-кроком. Жоден із наведених diagnostic результатів не є release acceptance.

## R6 100k — повний workload, schema-відхилення і performance fail

Детермінований same-version ZIP
`promin-1.0.0-alpha.4-heavy-verified-r6.zip` має SHA-256
`b0b23f3576b5118fdcf33c605b5d4e29e4e2539df537ceb8d3f83dcb89708f54`.
Fresh foreground run у
`D:\ProminValidation\alpha4-r6-100k-b0b23f3576b5-20260812T152137953Z`
завершив exact незменшений workload: EventStore HEAD `1604`, `200603` events,
`100000` physical files і `600` runtime queries. Storage measurements наявні для
`preflight`, `physical-generation`, `inventory`, `semantic-ingestion`, `projection`,
`runtime-queries` та фінального `result` checkpoint. Але sealed
`saturation-result.json` не був опублікований: launcher завершився
`LAUNCHER_REJECTED_NO_PASS_CREDIT` о `2026-08-12T17:56:11Z`.

Причина публікаційної відмови точна: четвертий елемент raw-artifact manifest,
`raw/continuation-state-manifest.jsonl`, фізично існує, але має законні для
stateless continuation `bytes=0`, `records=0` і SHA-256 порожнього payload
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
Стара Schema вимагала мінімум один byte для всіх ролей. Terminal failure receipt:
`evidence/saturation-failure.json`, SHA-256
`c16b3729056f7992da59dcf100bf46620aee9638e1ea8552eda020ddba623c54`;
його `receipt_digest` —
`5fbd02f233da781384cda44dfe73eca234ceb08cad870fc9d962d87bf04e0d98`.
R6 збережено як terminal rejected evidence і не підлягає повторному запуску або
ретроактивному зарахуванню.

Сам workload також чесно не вклався у profile `portable-local-v1`. Не пройшли
semantic ingestion `5399.621207 s > 600 s`, commit p95/p99
`4285.4479/9164.8388 ms > 500/1000 ms`, query p50/p95/p99
`483.5423/589.7476/828.9208 ms > 100/150/500 ms` та peak RSS
`1257553920 > 805306368` bytes. Отже schema seam не приховує окремий performance
fail: усі acceptance, product, public-release і pass-credit claims залишаються
`false`.

Вузький conditional-zero repair дозволяє лише ролі
`continuation-state-manifest` атомарну пару `(bytes, records)=(0, 0)` або обидва
додатні значення. Решта п'ять raw artifacts і generic JSONL parser залишаються
обов'язково непорожніми; empty parsing є явним opt-in лише для continuation.
Semantic validator зв'язує реальний payload, digest і точний summary
`files=maximum_bytes=total_bytes=0`; змішані `(0,1)/(1,0)`, підміна role/path/media,
неузгоджений summary та нульовий required artifact fail closed. Окремий focused
suite має `19 passed`; інтегрований repair-зріз — `22 passed, 35 deselected`.
Незалежний review завершився `PASS` без P1/P2 findings. Це доводить вузький repair,
але не є release або performance PASS.

Read-only exact r6 replay перед r7 виявив другий deterministic publication seam.
Producer правдиво записував фактичний versioned basename
`promin-1.0.0-alpha.4-heavy-verified-r6.zip`, тоді як semantic validator
hardcoded-очікував `promin.zip`. На незмінених ZIP bytes/SHA, candidate digest і
member closure старий validator відтворювано давав RED:
`EvidenceError: exact artifact archive binding is invalid`. Це була суперечність
label policy, а не зміна вмісту кандидата.

Repair повторно використовує portable safe-basename policy `final_admission` у
producer і validator: один NFC `.zip` filename без separator/traversal/NUL/colon,
reserved Windows stem або непереносного компонента. Фактичний basename лишається
частиною signed `binding_digest`; перевірки bytes, SHA-256, member closure і
candidate binding не змінені та не послаблені. Versioned r6/r7 basename проходить,
unsafe basename після повторного підпису fail closed. Focused suite:
`17 passed`; незалежний review завершився `PASS` без P1/P2 findings. Версія
незмінна, `acceptance_pass=false`, `performance_acceptance=false`,
`pass_credit=false`.

Версія не змінена: `1.0.0-alpha.4` / `1.0.0a4`. Поточні repair bindings:
Core bundle digest
`04df51b05013baa8a40e1425a13825261924e33d200ca5d1dbf972651b73bcdb`,
`core/contracts.schema.json` SHA-256
`5f95e0bc177c728e3edcd6faddde6716c4d7d527a68cfbb2b1980bcc87b26c41`.
Оновлений pre-refresh canonical inventory визначено як `246` files, `17`
directories і `91` test selectors;
package refresh та exact closure verification ще обов'язкові перед candidate r7.

Наступний допустимий scale-крок — лише новий deterministic r7 з повністю
перевіреної extraction, потім fresh foreground Windows exact 100k у новому root.
R6 workspace повторно не використовується. Навіть schema-valid terminal
`status=fail` не надає performance/product acceptance; після успішного terminal
100k ще потрібні незалежний audit, Windows aggregates ×2, modeled Linux/WSL,
fixed 72-bucket comparison, product inspection і клієнтський PDF.

## Truth tokens

```text
validation_claim=targeted_diagnostic_only
runtime_diagnostic_pass=true
acceptance_pass=false
visual_acceptance=false
performance_acceptance=false
pass_credit=false
g27_g45_pass_credit=false
authority_confirmed=0
authority_pending=required_final_runs
full_static_scan_deferred=true
mrets_layer=preserved
ugt_layer=additive
proxy_acceptance=false
```
