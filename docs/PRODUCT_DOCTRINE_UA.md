# Продуктова доктрина promin

> **Людина визначає сенс - агенти уточнюють і реалізують.**

promin приховує внутрішню строгість і показує користувачу лише мету, resolved
plan, стан, блокери та рішення, які справді потребують людини.

Стандартний шлях:

```text
мета / backlog / repository
-> bounded preflight без анкети й повного scan
-> один resolved plan
-> підтвердження або природномовне уточнення
-> Task DAG і bounded WorkCard
-> виконання, evidence, self-audit і наступна дія
```

Пріоритет визначення значень:

1. явні вимоги користувача;
2. факти repository та project-local конфігурації;
3. installed trusted profiles і skills;
4. Morok Tower Studio як fallback;
5. безпечний reversible default;
6. питання лише за material ambiguity без безпечного рішення.

Preset, skill, telemetry, projection або сильніша модель не можуть розширювати
authority. `unsafe-auto` означає відсутність зайвих питань у межах чинних прав,
а не відсутність контролю.
