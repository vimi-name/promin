# Переносимість: Windows verified; Linux/macOS declared, static-only

Поточний верифікований deployment scope alpha.4 — Windows. Linux і macOS
лишаються задекларованими portable targets у коді та CI, але для них немає
пред'явлених runtime, installability або deployment evidence. Тому жодне
твердження нижче про Linux/macOS не має acceptance або pass credit до окремої
перевірки на відповідному host. Windows-only scope є явним неблокуючим
звуженням доказу alpha.4.

Canonical state містить portable relative paths, UTF-8/NFC identifiers, Core і
profile digests, intent, Tasks, Findings, Decisions, events та evidence
references.

Host-local derived state містить executable/SDK paths, shell і filesystem
adapter, locks, caches, SQLite projection, telemetry та installed local skills.
Він не є source of truth і не комітиться.

Після копіювання папки на інший host не відбувається автоматичне
rehydration/replay. Для нового керівного стану потрібна окрема
owner-confirmed clean-reinitialization операція з верифікованим project
package; `promin doctor --repair` лишається лише діагностикою та локальним
derived-state repair.

На Windows clean-reinitialization boundary має runtime evidence. Для
Linux/macOS нижче наведено задекларовану статичну поведінку, яку ще не можна
подавати як operational verification. Doctor може:

1. виявити зміну host;
2. перевірити casefold, Unicode, reserved names, EOL і path conflicts;
3. перевизначити providers/SDK/tools;
4. запропонувати owner-confirmed clean reinitialization замість migration;
5. перебудувати лише локальну projection/cache поверх чинного Activation;
6. показати неавторитетний team seed без імпорту progress/lease/task;
7. повернути `ready`, `degraded` або `blocked` із конкретним remediation.

Doctor не змінює application code і не імпортує чужу authority автоматично.
