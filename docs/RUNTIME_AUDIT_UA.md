# Runtime audit і heartbeat

Команди:

```text
promin audit
promin audit --live
promin audit --since 24h
promin audit --plan
promin audit --record
promin status --watch
```

## Реалізовано в `1.0.0-alpha.4`

Repository findings:

- `large-file` — вимірює розмір і кількість рядків; це сигнал для перевірки відповідальності, а не автоматична вимога декомпозиції;
- `exact-duplicate` — групує byte-identical source-файли за SHA-256; видалення дозволене лише після перевірки runtime use та унікальної поведінки.

Self-observations:

- `operational-error` та інші CLI/runtime observations, агреговані за bounded fingerprint;
- heartbeat із кількістю активних fingerprints, retries і потребою людського рішення.

Repository findings і Promin self-observations виводяться окремо. Self-observation не підвищує severity repository finding і не створює pass credit.

## Заплановано, але не реалізовано в цій alpha

- planning-quality і duplicate-Task analysis;
- stale-evidence і technology-drift diagnosis;
- semantic/shadow implementation analysis beyond exact hashes;
- context/search, event/projection amplification;
- heartbeat-gap і portability-failure correlation.

Ці класи не повинні заявлятися як виконані до появи executable fixture і acceptance test.

Кожне твердження класифікується як `Verified`, `Measured`, `Inferred`, `Hypothesis` або `Unknown`. Повторні observations агрегуються за fingerprint; одна помилка не створює тисячі graph nodes.

За замовчуванням `promin audit` є read-only. Запис локального bounded результату виконується лише з `--record`. Telemetry можна вимкнути через `--no-telemetry` або `PROMIN_NO_TELEMETRY=1`.

Telemetry локальна, bounded і redacted. Вона не зберігає secrets, PII, повні prompts, production payloads або source bodies. Audit, heartbeat і generated reports не є authority й не дають pass credit.
