# Skills у promin

## Формат

Канонічний project skill:

```text
.promin/portable/skills/<skill-id>/
├── SKILL.md
├── promin.skill.json
├── scripts/       # optional
├── references/    # optional
└── assets/        # optional
```

`SKILL.md` містить процедуру у відкритому Agent Skills форматі.
`promin.skill.json` явно bind-ить version, SPDX license, capabilities, hosts,
platforms, required tools, security scope і content digest.

## Команди

```bash
promin skills list
promin skills request "потрібна можливість"
promin skills create my-skill --description "..." --instructions-file skill.md
promin skills install ./existing-skill --license Apache-2.0
promin skills install https://.../skill.zip --allow-network --sha256 <digest>
promin skills remove my-skill
promin skills sync
```

## Існуючі skills

promin metadata-only виявляє skills у:

- `.agents/skills/`;
- `.claude/skills/`;
- `.cursor/skills/`;
- відповідних user-local catalogs.

Вони залишаються host-provided і не стають authority. Щоб зробити skill
portable і Promin-managed, користувач явно виконує `promin skills install`.

## Безпека

- remote fetch вимкнений без `--allow-network`;
- дозволений лише HTTPS;
- exact SHA-256 обов'язковий;
- license обов'язкова;
- symlink, path traversal і casefold collision відхиляються;
- skill не може видати Grant або pass credit;
- actual operation обмежена Task, Grant, allowed paths і active profile.

Host wrappers короткі. Повний SKILL.md читається лише коли поточна Task справді
потребує цієї capability.
