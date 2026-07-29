# alpha.3 reconciliation-r2: B-1—B-3 локальна хвиля

## Активний scope

- B-1: `workspace_map` зберігає точні per-unit лічильники, а діагностичні списки технологій і source suffixes є детерміновано обмеженими.
- B-2: кожен ingress `ProjectInit` перевіряє глобальний Core budget для source samples; JSON Schema лишається структурним обмеженням, семантичний validator — aggregate defense in depth.
- B-3: дорогі alias/read-only temporary-tree перевірки винесені з `paths` у окремий `aliased-temp-tree` shard з timeout 600 s. `allowed_skips=0` і `unexpected_skip_policy=fail` збережені.

## Цільова валідація

| Command | Result | Notes |
|---|---|---|
| `python -B -m pytest -q tests/test_alpha3_workspace_budget.py tests/test_alpha3_ingress_budget.py tests/test_alpha3_reconciliation_static.py tests/test_alpha3_reconciliation_paths.py` | pass | 12 passed in 27.30 s; synthetic mixed workspace містить 3 units, 2,004 entries і >=10 технологій. |
| `python -B -m pytest -q tests/test_alpha3_reconciliation_aliased_temp_tree.py` | pass | 2 passed in 0.46 s; окремий lane вкладається у 600 s на поточному host. |
| `python -B tools/compile_schema.py . --check` | pass | schema projection не дрейфує. |
| `git diff --check` | pass | виконано перед integrity refresh. |
| `promin_package.py refresh <clean staging> --install-mode none` | pass | 133 canonical files, integrity closure=true, REC-006=pass; staging не містив `.git`. |
| `test_manifest_and_checksums_close_over_canonical_package_copy` | pass | 1 passed in 5.23 s. |
| `test_exact_archive_is_deterministic_and_cleanly_verifiable` | blocked | runner не повернув фінальний результат, пов'язані тестові процеси завершено; pass credit не надано. |

## Межі твердження

`validation_claim=targeted_pass`

`runtime_diagnostic_pass=true`

`acceptance_pass=false`

`visual_acceptance=false`

`performance_acceptance=false`

`pass_credit=false`

`g27_g45_pass_credit=false`

`authority_confirmed=0`

`authority_pending=8`

`full_static_scan_deferred=true`

`mrets_layer=preserved`

`ugt_layer=additive`

`proxy_acceptance=false`

Не виконано в цій хвилі: B-4/B-5 latency completion і promotion з `provisional`, physical 100k, A/B, saturation, performance shard, повний `pytest -m "not scale"`, а також macOS/Linux докази. Детерміністичний archive test заблокований runner-ом і не має pass credit. Поточний локальний результат не є production або public-release approval.
