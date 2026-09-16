# ADR-005 — BEMO Core boundary and the first inspector module

**Status:** ACCEPTED

## Context

Issue #14 sets the V1 product/architecture direction: DNS Inspector becomes
the first inspector inside a broader **Inspector BEMO** platform, alongside
future System, Storage, Services, Backup, Network, UPS, Media and Security
inspectors, with a correlation engine planned for later.

`docs/MODULARIZATION.md` already identified real module boundaries
(`config`, `status`, `external_links`, ...) as future work, ordered by how
safely each could be extracted from `app.py`. Issue #14 asks for the same
kind of extraction, but organized around inspectors rather than bare
top-level modules, plus a shared registration/health boundary those
inspectors register with.

## Decision

1. A new `bemo_core/` package holds only what is genuinely shared today:
   - `registry.py`: `InspectorInfo` (an inspector's static identity) and
     `InspectorRegistry` (an in-memory, idempotent-by-slug directory).
   - `health.py`: `HealthLevel` (`ok`/`warning`/`error`/`unknown`) and
     `InspectorHealth`, the generic health shape every inspector reports.
2. Observations, events, findings, evidence, and any inspector-plugin
   discovery mechanism are **not** introduced yet. With a single inspector,
   those primitives would be speculative; they are added when a second
   inspector's real requirements justify their shape.
3. `inspectors/dns/` is the first inspector boundary. Its first contents are
   exactly the modularization plan's Tier 1 `status` slice
   (`query_status`, `status_summary`, `severity_for_classification`,
   `_status_from_counts`) — pure, already tested, safe to move — plus
   `register()` and a thin `health()` aggregate. `app.py` imports these
   names back unchanged; no other DNS Inspector behaviour has moved.
4. The dashboard gains a minimal BEMO shell nav (platform branding plus the
   live registry contents) without altering the existing DNS Inspector
   views, and a new `/api/inspectors` endpoint exposes the registry as JSON.

## Consequences

- Future inspectors (System, Storage, Services, ...) register with
  `bemo_core.registry.get_registry()` and report health via
  `bemo_core.health.InspectorHealth`, rather than each inventing its own
  shape.
- Further DNS Inspector extractions (Tier 2/3 in `docs/MODULARIZATION.md`)
  land inside `inspectors/dns/` going forward, one focused boundary at a
  time, rather than as bare top-level modules.
- This ADR does not authorize building System/Storage/Services inspectors,
  the correlation engine, or the observations/events/findings data model.
  Those remain future, separately-scoped tasks per issue #14's delivery
  strategy.

## References

- Issue #14 — Inspector BEMO V1 product/architecture direction.
- `docs/MODULARIZATION.md` — Tier 1 `status` boundary and suggested sequence.
- `docs/ARCHITECTURE.md` — "Inspector BEMO" section.
