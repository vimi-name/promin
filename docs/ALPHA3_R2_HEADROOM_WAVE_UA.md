# alpha.3 reconciliation-r2: headroom після re-audit

Незалежний Opus re-audit B-1—B-3 закрив F-8 і F-9 без регресій, але зафіксував лише 5 B запасу на його реальному mixed-repository. Ця хвиля додає детермінований запас там, де він досяжний без втрати семантики.

## Зміна

- `repository_signals` мають точні `total_count`, `example_count_complete` і чесний `examples_truncated`; приклади лишаються діагностичною вибіркою.
- `_fit_resolved_plan_budget` спочатку зменшує діагностичні source/signal samples до 90% Core byte limit. Якщо структурно незвідний план не може досягти цього preference, жорсткий Core limit 8,192 B лишається fail-closed межею.
- Усі operation/model-tier pairs збережені; їхні причини лише скорочені, без зміни routing semantics.

## Цільова валідація

| Command | Result | Notes |
|---|---|---|
| `python -B -m pytest -p no:cacheprovider -q tests/test_alpha3_plan_headroom.py tests/test_alpha3_workspace_budget.py tests/test_alpha3_ingress_budget.py` | pass | 3 passed in 3.27 s. |
| `python -B tools/compile_schema.py . --check` | pass | Generated schema не дрейфує. |
| `git diff --check` | pass | Без whitespace defects. |

Focused fixture: >=4 units, >=12 technologies, 3,020 entries; canonical plan <=7,372 B (10% headroom), byte-identical при reversed preflight order, і exact large-source total=20.

`validation_claim=targeted_pass`

`acceptance_pass=false`

`visual_acceptance=false`

`performance_acceptance=false`

`pass_credit=false`

`proxy_acceptance=false`

Не виконано: B-4/B-5, full suite, performance/package shards, physical 100k, A/B, saturation, macOS/Linux та production/public-release acceptance.
