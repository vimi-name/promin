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
- Saturation route має storage preflight, 8 GiB fail-safe headroom, growth model, telemetry і fail-closed terminal receipt.

## Свіжа діагностична перевірка

- Derived storage: `9 passed`.
- Authority/Domain checkpoint: `4 passed`.
- Init/languages/weak-model: `34 passed`.
- Recovery/revalidation/publication: `48 passed, 1 skipped`.
- Provider/receipts/adversarial: `31 passed, 1 skipped`.
- Product inspection/minimality/comparison/Linux-model tests: `22 passed`.
- Windows EventStore persistence aggregate до останнього розширення: `88 passed, 1 skipped, 31 subtests passed`; після нього незалежний post-HEAD/batching/state-binding rerun: `14 passed`.
- Search-scale non-scale: `23 passed, 1 deselected, 29 subtests passed` на стабільному implementation closure.
- Exact package tree: 231 файл / 17 каталогів; `verify-tree --install-mode current-environment` валідний, версія `1.0.0-alpha.4`.

Пропуски не мають pass-credit. CodeRabbit review був недоступний через відсутню інтерактивну автентифікацію; ручний висновок не підміняє його.

## Виявлена зовнішня причина storage failure

WPR залишив два ETL payload загальним обсягом `212155236352` bytes (`197.585 GiB`). Вони були у 507 разів більші за failed Promin tree. WPR зупинено, stale test/workspace roots очищено. Це пояснює конкретний `SQLITE_FULL`, але не скасовує окремі intrinsic scale fixes вище.

## Відкладені докази

- свіжий exact same-version candidate ZIP;
- незменшений Windows 100000-file / 600-query run;
- два незалежні Windows non-scale layouts;
- modeled Linux validation у WSL/Docker;
- повний Promin vs Markdown vs empty benchmark;
- deterministic product-inspection receipts;
- короткий клієнтський PDF із зовнішніми receipt bindings.

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
