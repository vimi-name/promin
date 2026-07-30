# Переносимість: Windows verified; Linux/macOS declared, static-only

Поточний верифікований deployment scope alpha.3 — Windows. Linux і macOS
лишаються задекларованими portable targets у коді та CI, але для них немає
пред'явлених runtime, installability або deployment evidence. Тому жодне
твердження нижче про Linux/macOS не має acceptance або pass credit до окремої
перевірки на відповідному host. Windows-only scope є явним неблокуючим
звуженням доказу alpha.3.

Canonical state містить portable relative paths, UTF-8/NFC identifiers, Core і
profile digests, intent, Tasks, Findings, Decisions, events та evidence
references.

Host-local derived state містить executable/SDK paths, shell і filesystem
adapter, locks, caches, SQLite projection, telemetry та installed local skills.
Він не є source of truth і не комітиться.

Після копіювання папки на інший host очікуваний portable flow:

```text
promin doctor --repair
```

На Windows цей маршрут має runtime evidence. Для Linux/macOS нижче наведено
задекларовану статичну поведінку, яку ще не можна подавати як operational
verification. Doctor має:

1. виявити зміну host;
2. перевірити casefold, Unicode, reserved names, EOL і path conflicts;
3. перевизначити providers/SDK/tools;
4. виконати idempotent control-layer migration;
5. перебудувати projection/cache;
6. сформувати proposal для portable team state;
7. повернути `ready`, `degraded` або `blocked` із конкретним remediation.

Doctor не змінює application code і не імпортує чужу authority автоматично.
