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
