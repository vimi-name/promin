# Переносимий контекст і документаційний шар

## Принцип

```text
Git + короткі portable surfaces
→ Python context API
→ локальна rebuildable projection
→ bounded відповідь агенту
```

У Git зберігаються лише короткі файли, потрібні іншому розробнику або агенту:

```text
AGENTS.md
CLAUDE.md
.cursor/rules/promin.mdc
.agents/skills/promin*/SKILL.md
.claude/skills/promin*/SKILL.md
.cursor/skills/promin*/SKILL.md
.promin/docs/**
```

Events, SQLite, caches, provider receipts, telemetry payloads, absolute tool
paths і host bindings не комітяться.

## Пошук

Агент викликає:

```bash
promin context "точний запит" --unit mobile-android
```

Python є стабільним bridge. У alpha він використовує SQLite FTS5 external
content, а за відсутності FTS5 - JSONL fallback. Агент не залежить від SQL,
таблиць або конкретного backend.

Порядок retrieval:

1. exact ID/path;
2. bounded FTS ranking;
3. typed unit filtering;
4. explicit byte/token budget;
5. complete provenance у відповіді.

Повні skill instructions, source tree або весь repository не завантажуються без
потреби.

## Самооновлення

```bash
promin refresh
```

Refresh використовує Git/content hashes і оновлює лише invalidated semantic
units. Звичайний commit без зміни bytes не інвалідовує документацію.

Для повної регенерації лише derived шару:

```bash
promin refresh --reset-derived
```

Ця команда не повторює init, не змінює product code і не видаляє canonical
operational history.

## Бюджети alpha

- portable Git surface: не більше 2 MiB;
- startup host instructions: не більше 2 500 modeled tokens;
- default context response: 8 KiB;
- context projection: не більше 32 MiB;
- один source inventory для всіх derived surfaces.

Ці бюджети є guardrails alpha, а не універсальними performance claims.
