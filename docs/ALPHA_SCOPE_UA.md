# Обсяг promin 1.0.0-alpha.3

В alpha входять:

- no-question-first guided init;
- greenfield, existing-code і hybrid Candidate;
- mixed web/mobile/backend repository під одним control layer;
- Morok Tower Studio, Web, Android, Windows і Vibe Recovery profiles;
- ask, safe-auto й unsafe-auto;
- українська та англійська звітність;
- Task/Grant/Lease/WorkCard/evidence control loop;
- hash-driven documentation refresh і bounded context index;
- Codex, Claude та Cursor native pickup;
- portable/project-local skills;
- runtime audit, heartbeat і doctor repair;
- Windows portable canonical state — поточний верифікований deployment scope
  alpha.3.

Свідомо відкладено:

- runtime/deployment verification для Linux і macOS. Їх portable canonical
  state лишається задекларованою статичною сумісністю, а не підтвердженим
  operational claim; Linux/macOS CI lanes не дають deployment або acceptance
  credit без окремо пред'явлених артефактів;
- повторні physical 100k runs;
- довгі A/B кампанії;
- три повні saturation iterations;
- повну stable-release platform/performance matrix.

Відкладені перевірки мають статус `alpha_deferred`, `not_executed` і
`no_acceptance_credit`. Runtime telemetry допомагає знаходити проблеми в полі,
але не підмінює невиконані release tests.

Windows-only verified scope не є блокером alpha.3: це явне поточне звуження
доказу, а не твердження, що Linux або macOS не підтримуватимуться надалі.
