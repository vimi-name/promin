# Model routing

promin обирає мінімально достатній виконавець:

```text
deterministic tool
-> micro model
-> standard model
-> strong model
-> critical independent review
```

| Tier | Типова робота |
|---|---|
| `tool-only` | hash, schema, exact search, diff, formatting |
| `micro` | класифікація, механічні edits, короткі summaries |
| `standard` | bounded implementation, tests, routine review |
| `strong` | architecture, security, concurrency, semantic deduplication |
| `critical-review` | irreversible migration або release recommendation |

Назви конкретних моделей не прошиті в Core. Provider mapping задається init
фактами й може змінюватися без зміни Task semantics. Сильніша модель не отримує
додаткових прав. Escalation потребує evidence; після складної частини робота
повертається дешевшому tier.
