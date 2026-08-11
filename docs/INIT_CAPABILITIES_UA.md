# Capability profiles для init

`capability_profiles/standard-init.json` задає лише портативні, неавторитетні
defaults. Він не містить шляхів конкретного проєкту, хостових executable,
project ID або Capability Grant. `standing-reversible.json` також не видає
authority: він тільки класифікує дію перед уже обов'язковою перевіркою Grant,
Lease, WorkCard і effect scope.

## Детермінований вибір

Значення застосовуються строго у такому порядку:

1. Standard default;
2. host profile;
3. project-package default;
4. CLI override;
5. interactive-user choice.

Кожне effective поле має provenance. Project package може лише подати default;
CLI та інтерактивний вибір мають вищий пріоритет. `canonical_build_owners=1`
є invariant і не може бути override. Вибір `standing-reversible` не є alpha.4
profile: замість нього використовують `ask` або `standing-reversible`.

## Language contour

Language capability profile описує мови, рекомендовані documentation surfaces,
cheap required verification та optional verification. Під час init user явно
обирає для documentation і verification одне з `accept`, `decline` або
`custom`; у noninteractive режимі невирішене `ask` має бути відхилене до
publication. `custom` потребує непорожнього переліку tools.

Факт вибору tool не є доказом його наявності. Host probe повертає лише один з
`AVAILABLE`, `PASS`, `UNAVAILABLE`, `FAIL`, `SKIPPED`. `UNAVAILABLE` і всі
не-`PASS` стани мають `pass_credit=false`; навіть `PASS` не означає product або
release acceptance.

## Standing reversible autonomy

Профіль може дозволити без повторного питання лише визначену оборотну локальну
дію. Для запису в user-owned data потрібен recoverable backup. Будь-який
external effect, remote publication, dependency/license/trust-root change,
credential/payment або невідома/незворотна дія повертає
`OWNER_DECISION_REQUIRED`.

Таке рішення є додатковою fail-closed policy predicate. Воно не розширює
capability ceiling і не замінює Core authorization.

## H1: два UX для init profile

`promin.init_profiles.resolve_init_experience(...)` є чистим конфігураційним
швом. Він не запускає tool, не визначає мову за текстом або model output, не
створює Activation і не дає authority чи pass credit. Caller передає лише вже
явно обрані language ID: `c`, `cpp`, `csharp`, `java`, `javascript`, `python`.
Невідомий ID відхиляється до формування результату.

### Публічний CLI та fail-closed precedence

`promin init --yes` без capability-прапорців використовує `minimal` one-click.
Він не вимагає `--documentation` або `--verification`: після детермінованого
preflight він бере лише зареєстровані language ID з фактів технологій і
прив'язує generic references до плану. Відповідність є сталою:
`cpp`/`cmake` → `c`,`cpp`; `dotnet` → `csharp`; `java` → `java`;
`javascript`/`typescript`/`node` → `javascript`; `python` → `python`.
Невідомі технології не породжують language ID. Це не є model inference або
host probe; усі `model_inference_used`, `host_probe_performed`, authority,
pass-credit та acceptance-поля залишаються `false`.

Compact record, який потрапляє до canonical plan, до окремого реального host
probe має schema-compatible `status="UNAVAILABLE"`. Це означає лише відсутність
спостереження за tool, а не відсутність або відхилення вже зареєстрованого
generic selection; він не дає availability, pass-credit чи acceptance claim.

Повний public expert route вимагає всіх трьох явних частин:

```text
promin init --init-experience expert \
  --capability-language python \
  --capability-selections expert-selections.json --yes
```

`--capability-language` повторюється для кожного ID, а
`--capability-selections` (аліас `--capability-selection-json`) містить один
strict JSON object, ключі якого точно збігаються з переданими ID. Для кожної
мови обов'язкові рівно `capability_id`, `documentation` і `tools`; усі
references мають бути зареєстрованими, а required tool не можна прибрати.
Наприклад:

```json
{
  "python": {
    "capability_id": "python-language",
    "documentation": ["python-language-reference"],
    "tools": ["python-compile-check"]
  }
}
```

Precedence є fail-closed, без об'єднання різних UX:

1. Прихований повний expert plan route (`--standard-bundle` разом з усіма
   canonical plan inputs) є ексклюзивним і відхиляє guided capability options.
   Будь-який його окремий прапорець (`--activation-proofs`, `--emit-plan`,
   `--review-plan`, `--dry-run`) або partial canonical input без повного набору
   відхиляється до guided route й не виконує mutation.
2. Явний `--init-experience expert` відхиляє legacy
   `--documentation`/`--verification`/custom-tool options.
3. Явний `--init-experience minimal` також відхиляє legacy options.
4. Якщо `--init-experience` не задано, але задано legacy options, зберігається
   legacy deterministic path; якщо не задано нічого — використовується minimal.
5. `--documentation-tool` можливий лише з `--documentation custom`, а
   `--verification-tool` — лише з `--verification custom`; `custom` без
   відповідного непорожнього списку відхиляється. У legacy `--yes` як і раніше
   відхиляє unresolved `ask` до apply.
6. `--yes` і `--plan-only` взаємовиключні: команда відхиляється до будь-якого
   guided або hidden apply.

### Minimal one-click

`experience="minimal"` є default і не приймає expert selections. Для кожної явної мови він
детерміновано обирає один зареєстрований generic documentation reference і
мінімальний required generic tool reference. Порядок вводу не впливає на
результат або digest. Стан tool лишається `UNOBSERVED`: selection не є probe,
availability або доказом якості.

### Expert full override

`experience="expert"` вимагає повного явного selection для кожної переданої
мови: її незмінний `capability_id`, список documentation references і список
tool references. Кожен reference має належати до зареєстрованого generic набору;
required tool не можна прибрати. Semantic source дозволений лише як `owner`,
`cli` або `interactive-user`; `model` і будь-який інший source відхиляються.
Отже слабка модель не може непомітно обрати capability, documentation або tool.

Результат містить повний profile precedence
`default → host-profile → project-package → cli → interactive-user`, застосовані
sources/provenance, capability precedence, окремі selection digest і загальний
`experience_digest`. Усі authority, acceptance та pass-credit поля залишаються
`false`; результат має лише `CONFIGURED_PENDING_HOST_OBSERVATION` і потребує
окремого реального host probe та відповідних нормальних gate для будь-яких
подальших тверджень.
