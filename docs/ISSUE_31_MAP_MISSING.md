# Issue 31 — 0.8.5.1 map missing from live Analytics UI

Temporary handoff for the current `dev` build.

The operator reports that after updating the DEV container to 0.8.5.1, Analytics has no DNS Destinations map visible at all.

Facts verified in source:
- `dev` is 0.8.5.1.
- The 0.8.5.1 source contains the DNS Destinations widget, `/api/analytics/map`, and client map rendering.
- Dashboard layout persistence/presets may affect visibility and must be inspected.

Investigate and implement the root-cause fix on current `dev`. Ensure the map is visibly present by default on a current deployment, while preserving legitimate user customization. Verify widget markup, layout loading/presets, route, client fetch/render, and empty/no-GeoIP behavior. Add focused regression tests and run the full suite. No unrelated BEMO work. Commit/push a dedicated branch and open a PR to `dev`; do not merge.