# Skills

promin can discover existing native host skills and manage portable or
host-local skills. A managed skill contains:

```text
<skill-id>/
├── SKILL.md
├── promin.skill.json
├── scripts/       # optional
├── references/    # optional
└── assets/        # optional
```

Every skill binds a stable ID/version, content digest, SPDX license,
capabilities, compatible hosts/platforms, required tools, entry point, and
security scope. Skills never grant authority or pass credit.

Commands:

```text
promin skills list
promin skills request "requirement"
promin skills create NAME --description TEXT --instructions-file FILE
promin skills install SOURCE [--sha256 DIGEST] [--allow-network]
promin skills remove NAME
promin skills sync
```

Remote installation requires explicit opt-in, HTTPS, and exact SHA-256.
