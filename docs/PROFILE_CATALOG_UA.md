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

Система може змінити композицію лише з trusted installed layers, із provenance
та compatibility check. Profile revision не може розширити authority ceiling.
