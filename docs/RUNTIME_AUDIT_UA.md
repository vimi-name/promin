# Runtime audit і heartbeat

Команди:

```text
promin audit
promin audit --live
promin audit --since 24h
promin audit --plan
promin status --watch
```

Audit спостерігає planning quality, retries/loops, stale evidence, technology
drift, duplicate work, source-of-truth ambiguity, context/search degradation,
event/projection amplification, heartbeat gaps і portability failures.

Кожне твердження класифікується як `Verified`, `Measured`, `Inferred`,
`Hypothesis` або `Unknown`. Повторні observations агрегуються за fingerprint;
одна помилка не створює тисячі graph nodes.

За замовчуванням telemetry локальна, bounded і redacted. Вона не зберігає
secrets, PII, повні prompts, production payloads або source bodies. Audit,
heartbeat і generated reports не є authority й не дають pass credit.
