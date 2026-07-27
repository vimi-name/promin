# Security policy

## Reporting

Do not publish suspected vulnerabilities, credentials, personal data, or raw
production payloads in public issues. Use a private repository security
advisory or another private channel controlled by the repository owner.

## Alpha guarantees

- Default-deny authority and explicit scoped Grants.
- No hidden privilege escalation by presets, skills, reports, or projections.
- No production data, secrets, full prompts, or source bodies in telemetry by default.
- Remote skill installation requires explicit network opt-in and an exact SHA-256.
- Canonical state uses portable relative paths; host-specific paths are derived.
- Failed, skipped, blocked, stale, or unresolved evidence receives no pass credit.

Only the newest `alpha` branch revision is supported during the alpha phase.
