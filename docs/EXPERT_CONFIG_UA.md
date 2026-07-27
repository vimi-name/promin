# Expert configuration

Звичайний користувач не редагує внутрішні контракти. За потреби команда може
виконати:

```text
promin init --emit-expert-config DIRECTORY
```

Expert view містить окремих власників:

- project intent, roots, references і work sources;
- resolved profile та explicit overrides;
- technologies/providers і license bindings;
- authority та autonomy policy;
- orchestration/model routing;
- telemetry/retention;
- Activation.

Правила:

- generated expert files є proposal до apply;
- усі resolved defaults видимі;
- жодних абсолютних host paths у portable canonical state;
- зміни перегенеровують цілісний plan, а не накопичують приховані overrides;
- preset або host config не можуть мовчки розширити authority.
