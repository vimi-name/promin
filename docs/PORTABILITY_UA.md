# Переносимість Windows / macOS / Linux

Canonical state містить portable relative paths, UTF-8/NFC identifiers, Core і
profile digests, intent, Tasks, Findings, Decisions, events та evidence
references.

Host-local derived state містить executable/SDK paths, shell і filesystem
adapter, locks, caches, SQLite projection, telemetry та installed local skills.
Він не є source of truth і не комітиться.

Після копіювання папки на інший host:

```text
promin doctor --repair
```

Doctor повинен:

1. виявити зміну host;
2. перевірити casefold, Unicode, reserved names, EOL і path conflicts;
3. перевизначити providers/SDK/tools;
4. виконати idempotent control-layer migration;
5. перебудувати projection/cache;
6. сформувати proposal для portable team state;
7. повернути `ready`, `degraded` або `blocked` із конкретним remediation.

Doctor не змінює application code і не імпортує чужу authority автоматично.
