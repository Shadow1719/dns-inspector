# AI Development Contract

## Source of truth

The Git repository is the canonical source of truth for DNS Inspector.

This applies to every AI agent working on the project, including ChatGPT, Claude Code, and any future coding agent.

If conversation memory, previous prompts, generated summaries, or remembered project state conflicts with the repository, the repository wins.

Do not reconstruct current architecture or implementation from memory.

## Required context order

Before making or reviewing an implementation change, establish context in this order:

1. `AGENTS.md`
2. `CLAUDE.md` when using Claude Code
3. `docs/CURRENT_STATE.md`
4. relevant architecture and design documents
5. relevant task/decision documents
6. the actual source code and tests
7. recent Git history when ownership, behaviour, or intent is unclear

The documents describe intent and decisions; the source code remains authoritative for what is actually implemented.

## Authority rules

Use these sources for these questions:

- **Current implementation:** source code + tests
- **Current project state:** `docs/CURRENT_STATE.md`
- **Architecture:** `docs/ARCHITECTURE.md` and actual source code
- **Architectural decisions:** `docs/DECISIONS.md` and `docs/decisions/`
- **Product direction:** `ROADMAP.md`
- **Historical change:** Git history / changelog

When documentation and implementation disagree, do not silently choose one. Report the mismatch and determine which is current from Git history or the task context before changing code.

## Implementation discipline

- Inspect before editing.
- Make the smallest correct change that satisfies the task.
- Do not invent modules, APIs, abstractions, or architecture that are not supported by the repository.
- Do not perform an unrelated refactor while implementing a focused fix.
- Preserve existing behaviour unless the task explicitly requires changing it.
- Never use wildcard imports to obtain private implementation globals.
- Do not create a second source of truth in an AI conversation or AI memory.

## Validation

After implementation:

1. run the most relevant targeted tests;
2. run broader tests when practical;
3. inspect the resulting diff;
4. update project documentation if the architecture, behaviour, or project state changed;
5. report exactly what changed and what was validated.

Never claim a test passed unless it was actually run.

## Collaboration protocol

ChatGPT and Claude Code are separate AI instances. They do not share conversation state or memory.

They synchronize through Git.

ChatGPT may propose architecture, decisions, plans, reviews, or task contracts. Those decisions are not authoritative until represented in repository files or code.

Claude Code may implement approved work and update the repository. Its implementation becomes canonical only after it is represented in Git.

A useful hand-off therefore follows this chain:

`decision -> task/ADR -> implementation -> tests -> Git commit -> updated current state`

Do not require the human to manually copy long conversational context between agents when the same information can be recorded in the repository.

## Task status

Task documents should make their state explicit, for example:

- `PROPOSED`
- `READY`
- `IN_PROGRESS`
- `BLOCKED`
- `IMPLEMENTED`
- `SUPERSEDED`

A task marked `READY` is an implementation contract, not permission to broaden scope.
