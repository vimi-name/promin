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
