# promin 1.0.0-alpha.3: виправлення за повторним зовнішнім аудитом Opus 5

Ця ітерація закриває локальні технічні зауваження alpha.3, але не є заявою
про публічний або стабільний реліз. Незалежний повторний аудит лишається
окремим доказом.

## Єдиний власник path identity

- Provider-ідентичність проходить через `promin.platform_paths.resolve_identity_path`.
- Windows extended-length prefixes є transport spelling лише під час запуску
  `subprocess`.
- Provider records, receipts, healthchecks та порівняння зберігають звичайну
  canonical identity.
- Shared provider-store root фізично резолвиться на верифікованому Windows
  маршруті; Linux/macOS branches задекларовані статично, але не мають runtime
  або deployment pass credit.
- Конкурентні `_provider_path`, `_configured_provider_path` та
  `abspath`-normalization видалені.

## Глобальний бюджет resolved plan

`resolved_plan_source_samples_max = 64` — це єдиний глобальний бюджет sampled
paths усього resolved plan, а не квота кожної технології. Кожна technology
зберігає точний `total_source_count`; samples розподіляються детерміновано,
можуть бути скорочені до порожнього списку й не перевищують 8192 canonical
bytes для всього plan. Усі ingress-маршрути plan перевіряють ці інваріанти
перед застосуванням, компіляцією, експертним виводом або записом.

## Вимірювані command contracts

Єдиний власник — `command_latency_contracts` у `core/conformance.json`.
Кожен запис містить точні command, `cli_cold` / `runtime_warm` /
`operation_incremental` mode, bounded workload, p95 budget, кількість
warm-up і measured runs, provider/projection state та `enforced` або
`provisional` status. `validate` має окремі cold і warm записи.

`tools/promin_command_bench.py` вимірює лише bounded local fixture: cold
samples створюють нові процеси, а warm samples повторно використовують один
`ProminService`. Це діагностичне локальне evidence; кожен результат має
`pass_credit=false`, `product_acceptance_pass=false` та
`public_release_approved=false`.

## Portability evidence

Поточний верифікований deployment scope — Windows; Windows-only scope є
неблокуючим звуженням доказу alpha.3. CI має окремі static, path, Windows
integration, performance та package lanes. Ubuntu/macOS portability jobs є
non-normative declared compatibility lanes: без окремо пред'явлених артефактів
вони не доводять Linux/macOS installability, deployment або acceptance.
Windows lane використовує одну session-scoped install fixture, 8.3/alias TEMP
і cache roots та deep project root. Несподіваний skip є помилкою, а не
кредитом.

## Межа доказу

Локальний пакет доводить лише зафіксовані локальні маршрути. Фізичні 100k,
A/B і repeated saturation залишаються `alpha_deferred` без pass credit.
Незалежне Linux/macOS виконання, branch integration та cross-host re-audit
мають бути виконані окремо; до того Linux/macOS лишаються declared,
static-only targets без pass credit.
