# Каталог profiles

Активна конфігурація - revisioned `ResolvedProfile`, а не одна жорстко
зафіксована назва. Порядок композиції:

```text
explicit user requirements
-> project-local rules
-> detected technology facts
-> domain/workflow/platform layers
-> autonomy/language layers
-> generic language/capability fallback
-> safe reversible defaults
```

Bundled layers:

- `general-development` - evidence-first, bounded work, single source of truth;
- `c-family-development` - C/C++ language capabilities, documentation і verification contours;
- `web-application` - React/JS/TS/Supabase, web security і RLS review;
- `android-application` - Kotlin/Java/Gradle/Android SDK, permissions і tests;
- `mobile-application` - React Native/Expo, mobile permissions, signing і OTA review;
- `windows-development` - Visual Studio/MSBuild/CMake/PowerShell і path rules;
- `vibe-recovery` - provenance, semantic dedup, no blind merge;
- `ask`, `standing-reversible`;
- `uk`, `en`.

## Generic language capability profiles

`language_profiles/` contains strict capability profiles without a project ID,
source path, or product-specific default:

- `c-family-semantic` — C and C++;
- `csharp-semantic` — C#;
- `jvm-semantic` — Java, Kotlin, Scala, and Groovy;
- `javascript-typescript-semantic` — JavaScript and TypeScript;
- `python-semantic` — Python;
- `open-source-tooling` — build, documentation, and static-analysis contours;
- `weak-host-fallback` — a minimal portable contour for a constrained host.

Every profile keeps acceptance and release claims `false`, keeps diagnostic and
forensic detail host-local, and requires explicit user or project selection. A
missing optional tool has typed status `UNAVAILABLE`, never `PASS`, and cannot
receive pass credit.

Система може змінити композицію лише з trusted installed layers, із provenance
та compatibility check. Profile revision не може розширити authority ceiling.
