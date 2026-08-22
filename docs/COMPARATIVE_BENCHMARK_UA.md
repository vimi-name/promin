# Порівняльне вимірювання Promin

`tools/promin_comparative_bench.py` — локальний, повторюваний benchmark для
порівняння трьох визначених workflow. Це інструмент збору evidence, а не
release gate. Будь-який його JSON — включно з повністю виконаним — містить:

```json
{
  "claim": false,
  "pass_credit": false,
  "acceptance_pass": false,
  "product_acceptance_pass": false
}
```

Вимірювання не може саме по собі проголосити Promin швидким, готовим до
продукції або кращим за інший підхід. Таке рішення потребує окремого розгляду
конкретного artifact, хоста та повного набору доказів.

## Запуск

Без `--execute` команда нічого не вимірює: вона виводить лише повний протокол
з `execution.performed=false`. Це зручна перевірка параметрів перед важким
локальним запуском.

```powershell
py -3.14 tools/promin_comparative_bench.py --output C:\Temp\promin-comparative-plan.json
```

Для вимірювання використовуйте щонайменше три строго зростаючі розміри.
Значення за замовчуванням — 16, 64 і 256 Markdown-документів, один warm-up та
три зараховані повтори для кожної комбінації.

```powershell
py -3.14 tools/promin_comparative_bench.py `
  --execute `
  --sizes 16,64,256 `
  --warmup-runs 1 `
  --measured-runs 3 `
  --output C:\Temp\promin-comparative.json
```

Без `--fixture-root` фікстури створюються в приватному temporary directory і
видаляються після запису JSON. `--keep-fixtures` зберігає автоматично створену
папку та вказує її в результаті. `--fixture-root` приймає лише порожню папку;
інструмент відмовляється перезаписувати непорожній шлях.

Для швидкого технічного smoke можна обмежити scope, але такий JSON матиме
`execution.full_comparison_scope_selected=false` і не є повним порівнянням:

```powershell
py -3.14 tools/promin_comparative_bench.py `
  --execute --sizes 1,2,3 --warmup-runs 0 --measured-runs 1 `
  --scenarios empty --operations query
```

Фіксований повний route має рівно 72 унікальні bucket keys:
`scenario × operation × temperature × size` для 3 сценаріїв, 4 операцій,
`cold`/`warm` і розмірів 16, 64, 256. Звіт перевіряє closure цих ключів
(`missing`, `unexpected`, `duplicate`) без надання claim або pass credit.
Власні sizes, scenarios чи operations є лише diagnostic-only partial runs і
не є fixed full route.

## Точний протокол

Для `promin` і `markdown` перед кожним зразком інструмент створює однаковий
детермінований corpus: `README.md` та рівно `size` Markdown notes. Ця
підготовка не входить у timed interval. Кожен зразок має окрему фікстуру, тому
попередній запис, cache або індекс не переходить до наступного зразка.

| Операція | Promin | Classic Markdown-only | Empty baseline |
| --- | --- | --- | --- |
| `init` | public CLI handler `promin init --yes` з явними `documentation=decline`, `verification=decline` | побудова детермінованого `docs/INDEX.md` | створення та перевірка порожнього root |
| `update` | одна зміна source, потім public CLI handler `promin refresh` | одна зміна source, потім перебудова `INDEX.md` | scan порожнього root |
| `query` | public CLI handler `promin context "comparative benchmark"` після реального `refresh` precondition | лінійний пошук тексту в Markdown | scan порожнього root, результатів рівно 0 |
| `docs` | public CLI handler `promin refresh` з initialized source state | побудова детермінованого `INDEX.md` | scan порожнього root |

Це **не** твердження, що три сценарії функціонально еквівалентні. Promin
виконує authority/control/documentation/context роботу; Markdown baseline має
тільки визначену файлову операцію, а empty baseline показує нижню межу
filesystem/worker overhead. Саме тому JSON не містить автоматичного winner,
budget verdict або pass.

Для Promin route harness викликає його public CLI command handler та перевіряє
реальний результат: `init` мусить створити `.promin/init/activation.json`, а
`context` мусить знайти відомий benchmark content. Якщо closure, init або query
падають, sample фіксується як `failed`; harness не підміняє його нульовою
латентністю чи успішним surrogate.

## Cold, warm і ресурси

- `cold`: worker, який готував стан, завершується. Вимірювану операцію відкриває
  свіжий Python worker. Це вимір isolated process state, не виданий за повний
  shell-launch benchmark.
- `warm`: один worker готує та вимірює повторні ізольовані samples. За
  стандартних трьох repeats це показує процес після першої операції, але root
  кожного sample залишається новим.
- `wall_ms` — `perf_counter_ns`; `cpu_ms` — `process_time_ns` реального worker;
  це не system-wide CPU utilization.
- На Windows RSS читається через `PSAPI GetProcessMemoryInfo`; на Linux — через
  `/proc/self/statm`. Результат містить `baseline_bytes`,
  `peak_sampled_bytes`, `incremental_peak_bytes`, interval та source. Якщо
  платформа не дає поточний RSS, поля містять `null`/`available=false`, а не
  вигадані нулі.
- `storage_*` — сума regular files без переходу через links; окремо надається
  total, Markdown і `.promin` control bytes.

Виконання на Windows та Linux передбачене стандартною бібліотекою. На macOS
runtime-перевірку цього route не заявлено: нездатність зняти current RSS має
лишитися `unavailable`, доки її не підтвердять на реальному macOS host.

## Percentiles та scaling review

Кожний успішний bucket `scenario × operation × temperature × size` містить
власні raw samples і лінійно інтерпольовані `p50`, `p95`, `p99` для wall time,
CPU, sampled RSS та storage. Warm-up samples записуються окремо і не входять у
percentiles.

Після запуску з трьома або більше sizes утворюється
`scaling_checks[].p95_intervals[]`. Для кожної сусідньої пари він містить:

- `workload_factor`;
- `p95_latency_factor`;
- `p95_log_slope`;
- `superlinear_indicator` при slope > 1.20.

`superlinear_indicator` — лише сигнал для аналізу шуму, I/O, cache та реальної
складності. Сам check має `status=review-required`, `claim=false` і ніколи не
виносить PASS/FAIL verdict автоматично.

## Інтерпретація failure

Якщо Promin init не проходить, наприклад через implementation-closure drift,
результат повинен містити `status=failed` і причину в конкретному sample.
Порівняння інших сценаріїв може завершитися, але
`execution.all_samples_succeeded=false`; це partial evidence, не підстава
відкинути failure або приписати Promin credit.

Перед передаванням результату аудитору зберігайте exact JSON, команду,
`environment`, параметри, candidate identity та стан worktree окремим
підписаним evidence пакетом. Цей harness навмисно не створює такого approval
пакета сам.
