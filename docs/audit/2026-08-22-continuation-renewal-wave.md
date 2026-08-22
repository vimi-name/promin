# Continuation renewal wave — 2026-08-22

## Scope

The preserved r10 exact Windows 100k run reached its semantic workload but
terminated before a terminal saturation result because its fixed 900-second
continuation chain expired. This wave adds authenticated pre-expiry renewal
without changing the Promin version, workload cardinalities, Core TTL limits,
or any acceptance threshold.

## Implemented boundary

- `Projection.renew_search` reissues only a still-valid signed search token,
  preserving its cursor and exact search binding.
- `ProminService.renew_search` re-authorizes the current subject, grant,
  capability, scope, revocation epoch, Activation, HEAD and projection state.
- The saturation harness renews only inside the 30-second safety window and
  fails closed for expired tokens or for a runtime that lacks required renewal.
- Renewal evidence validates canonical token shape, Core token-byte ceiling,
  canonical UTC timestamps, snapshot and authorization bindings, and complete
  entity/relation/evidence payload identities across forced and reference
  chains.

## Verification performed

- Independent source review found the initial incomplete binding and
  losslessness checks; remediation underwent a second independent review with
  `CLEAN FOR TIER-A` verdict.
- Controlled focused renewal/projection run: `11 passed, 48 deselected` in
  162.14 seconds.
- Canonical selector/inventory run: `13 passed` in 4.99 seconds.
- Search-scale workcard/mixed-plan route: `2 passed, 23 deselected` in 1.35
  seconds.
- Exact package closure was refreshed twice with identical resulting hashes;
  strict `promin_validate.py . --install-mode none` returned `valid=true`.

## Evidence boundary

The deliberately over-broad aggregate exceeded its 600-second per-process
budget before terminal output and was stopped with its external log preserved;
it receives no pass credit. r10 remains preserved and rejected; it was not
reused, restarted or deleted. This wave is a correctness repair and Tier-A
functional evidence only. `acceptance_pass=false`,
`performance_acceptance=false`, and `pass_credit=false` remain binding until a
fresh r11 exact Windows 100k run completes with an independent terminal audit.
