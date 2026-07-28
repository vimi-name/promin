# promin 1.0.0-alpha.3: виправлення за повторним зовнішнім аудитом Opus 5

Ця ітерація реалізує загальні виправлення для блокерів `alpha.2`, виявлених на незалежному Windows-хості. Остаточне закриття має підтвердити повторний незалежний аудит. Виправлення не містять назв, шляхів або доменної логіки stress-repository.

## Єдиний власник path identity

- Уся provider-ідентичність проходить через `promin.platform_paths.resolve_identity_path`.
- Windows extended-length prefixes є лише transport spelling у момент `subprocess` launch.
- Provider records, receipts, healthchecks та comparisons зберігають звичайну canonical identity.
- Shared provider-store root фізично резолвиться в усіх Windows/macOS/Linux branches.
- Конкурентні `_provider_path`, `_configured_provider_path` та `abspath`-normalization видалені.

## Глобальний бюджет плану

`technology_source_items_max = 64` є глобальним budget усього resolved plan, а не окремою квотою кожної технології. Кожна technology зберігає exact `total_source_count`; sampled paths детерміновано розподіляються та скорочуються, доки повний plan не вкладається у `resolved_plan_bytes_max = 8192`.

## Вимірювані latency contracts

Кожний command latency budget має точне workload definition: cold/warm mode, maximum files, maximum input bytes та опис дозволеної підготовки. `audit_small` тепер означає bounded audit до 2 000 файлів і 256 MiB без network/install operations.

## Portability evidence

CI містить окремі host-alias lanes:

- Windows junction-aliased `TEMP` і `LOCALAPPDATA` плюс deep project root;
- macOS symlinked temp/cache roots;
- Python 3.12 і 3.13;
- повний non-scale corpus та Alpha.3 Opus closure suite.

## Межа доказу

Локальний пакет може довести Linux/focused behavior. Реальне Windows/macOS виконання, branch integration і cross-host re-audit мають бути повторно виконані на незалежних хостах. Невиконані physical 100k, A/B і repeated saturation залишаються `alpha_deferred` та не отримують pass credit.
