# DNS Inspector — Architecture Decisions

This file is the index of accepted project-level decisions. Detailed decisions may live under `docs/decisions/`.

## ADR-001 — Git repository is the project SSOT

**Status:** ACCEPTED

The Git repository is the canonical source of truth for project state, implementation, architecture documentation, decisions, and task contracts.

ChatGPT memory, Claude Code conversation history, previous prompts, and generated summaries are advisory only. They must never be treated as authoritative when they conflict with Git.

### Consequences

- Separate AI instances synchronize through repository state.
- Important decisions must be recorded in Git rather than left only in chat.
- The source code remains authoritative for actual implementation.
- `docs/CURRENT_STATE.md` records current project state without replacing the source code.

## ADR-002 — AI collaboration uses repository hand-offs

**Status:** ACCEPTED

ChatGPT and Claude Code have different runtime conversations and memories. The project therefore uses explicit repository hand-offs rather than attempting to synchronize model memory.

### Hand-off protocol

1. ChatGPT identifies or proposes a decision.
2. An accepted decision is recorded as an ADR or task contract.
3. A task may be marked `READY` for implementation.
4. Claude Code reads the repository contract and actual source before implementing.
5. Claude Code runs validation and commits the result.
6. The resulting commit becomes the canonical implementation state.
7. Current-state and architecture documentation are updated when materially changed.

### Consequence

The human should not need to manually copy large amounts of project context between AI instances when that context can be represented in the repository.

## ADR-003 — Documentation does not override code silently

**Status:** ACCEPTED

Architecture and state documents describe intent and known state, but the actual source code and tests determine what is implemented. If documentation and implementation disagree, the agent must identify the discrepancy and resolve it using Git history/task context rather than silently assuming either side is correct.

## ADR-004 — Focused tasks must remain focused

**Status:** ACCEPTED

A task contract defines its scope and constraints. An implementation agent must not expand a focused bug fix into an unrelated refactor merely because another improvement appears desirable. Broader architectural work should be a separate task/decision.

## ADR-005 — BEMO Core boundary and the first inspector module

**Status:** ACCEPTED

Established `bemo_core/` (inspector registry, generic health/status) and `inspectors/dns/` (the first inspector boundary, currently the query-status/severity classification slice) as the first implementation step of the Inspector BEMO V1 direction (issue #14). Observations, events, findings and evidence primitives are deliberately deferred until a second inspector needs them. See `docs/decisions/ADR-005-bemo-core-boundary.md` for the full decision.
