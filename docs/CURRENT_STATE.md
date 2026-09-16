# DNS Inspector — Current State

> This file records the repository's current project state for all AI agents. It is not a replacement for the source code. When this file conflicts with the implementation, investigate the repository and Git history before changing code.

## Baseline

- Repository: `Shadow1719/dns-inspector`
- Working branch: `dev`
- Foundation version: `0.8.0`
- Current version: `0.9.0-dev.1` — first Inspector BEMO migration slice (issue #14)
- AI collaboration contract: `AGENTS.md`
- Claude Code instructions: `CLAUDE.md`

## Architecture state

The 0.8.0 repository contains the complete application source; the historical generated Docker patch chain is no longer the runtime source of truth. The current architecture document records the concrete implementation map and the intended responsibility boundaries.

The application is still structurally centered on `app.py`, with recognizable regions for configuration, UI, database helpers, AdGuard access, device/IP identity, ingestion, reachability, enrichment, presentation, analytics, workers/routes, diagnostics, and the entry point. Modularization is an active architectural direction, not a claim that those regions are already independent modules.

As of `0.9.0-dev.1`, two real module boundaries exist alongside `app.py`:
`bemo_core/` (shared inspector registry and health/status primitives) and
`inspectors/dns/` (the first inspector boundary, currently holding the
query-status/severity classification slice and DNS inspector registration).
See "Inspector BEMO" in `docs/ARCHITECTURE.md` for the concrete map. The rest
of DNS Inspector's behaviour has not moved yet — this is a first slice, not
a completed migration.

## Important architectural principles

- DNS Inspector observes AdGuard activity; it is not an AdGuard policy editor or blocking engine.
- Background ingestion belongs outside the browser request path.
- Persistent state is local SQLite; unnecessary writes and repeated reconciliation should be avoided.
- External enrichment is asynchronous and cached.
- Unknown is neutral and must not be presented as malicious without evidence.
- Confidence and severity are separate concepts.
- Findings are advisory and explainable.
- Read-only-by-default behaviour is preferred.

See `docs/ARCHITECTURE.md` for the detailed architecture and `docs/MODULARIZATION.md` for the structural migration plan.

## Current development direction

The project is evolving from a DNS dashboard toward the Inspector BEMO platform, with DNS Inspector as the first mature mini-inspector. The roadmap defines the broader product direction and should be treated as product intent rather than a statement that every planned feature already exists.

Issue #14 is the accepted V1 product/architecture direction for this migration (see `docs/decisions/ADR-005-bemo-core-boundary.md`). `0.9.0-dev.1` is its first implementation slice: BEMO Core, a shared UI shell nav, and the first `inspectors/dns` boundary. System, Storage, Services and the other inspectors listed in issue #14 do not exist yet — only DNS is registered.

## Current collaboration state

ChatGPT and Claude Code are separate AI instances. They share no conversation memory. GitHub is the synchronization boundary.

The canonical hand-off is:

`decision -> task/ADR -> implementation -> tests -> Git commit -> current-state update`

Do not rely on either model's memory to preserve project-specific decisions.

## Branching model

- `main` is the production/release branch.
- `dev` is the active development/integration branch.
- Feature/fix branches are created from `dev` and target `dev`.
- Development work must not be committed directly to `main`.

The previous `dev-0.8` branch name is retired as the active development branch.

## Recent implementation note

The repository recently underwent a modularization/observability refactor. Focused fixes must be based on the actual code at the requested commit/branch, not on older ZIP archives or remembered pre-0.8 structure.

## How to update this file

Update this document when a change materially alters the project's current architecture, active development state, or important known constraints. Do not turn it into a changelog or duplicate the source code.
