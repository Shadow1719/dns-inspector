# ADR-001 — Git Is the Project SSOT

**Status:** ACCEPTED

## Decision

The Git repository is the canonical source of truth for DNS Inspector project state and implementation.

ChatGPT and Claude Code are separate AI instances. Their conversation histories and memories are not synchronized. They synchronize through Git repository state.

## Practical rule

If an AI remembers one thing but the repository says another, the repository must be inspected and resolved as the authority. An agent must not silently restore remembered state.

## Collaboration loop

```text
ChatGPT decision / plan
        ↓
Git task or ADR
        ↓
Claude Code reads repository
        ↓
implementation + tests
        ↓
Git commit
        ↓
repository becomes new canonical state
        ↓
ChatGPT can review the commit/repository
```

## Why

This prevents model memory drift and avoids requiring the human to copy large amounts of context between independent AI sessions.
