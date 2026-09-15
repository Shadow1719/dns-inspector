# DNS Inspector 0.8 modular architecture

Dev.16 introduces a module boundary around the high-risk runtime paths while
keeping the existing Flask UI as a compatibility shell during migration.

## Current module ownership

- `dnsinspector/db`: SQLite connection, WAL, schema and tracker snapshot access.
- `dnsinspector/services/ingest`: AdGuard query-log ingest and worker loop.
- `dnsinspector/services/devices`: device identity, device/IP relations and ping.
- `dnsinspector/services/domains`: domain status/classification/inspection.
- `dnsinspector/services/analytics`: read-only dashboard aggregation.
- `dnsinspector/services/enrichment`: enrichment boundary.
- `dnsinspector/services/adguard`: AdGuard API boundary.
- `dnsinspector/services/observability`: diagnostics boundary.
- `dnsinspector/services/ui`: HTML rendering helpers.

The remaining Flask routes/templates are temporarily supplied by
`legacy_app.py`. This is deliberate: it lets us migrate one subsystem at a
time without changing the public URL surface in the same release.

## Change rule

A normal feature change should touch only the owning service plus its tests.
Changes to the database schema, public API contracts, or shared rendering
helpers are cross-module changes and must be reviewed as such.
