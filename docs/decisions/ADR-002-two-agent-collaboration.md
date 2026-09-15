# ADR-002 — Two-Agent Collaboration Through Git

**Status:** ACCEPTED

## Decision

ChatGPT and Claude Code are treated as independent agents with no shared conversational memory.

ChatGPT is primarily used for architecture, planning, review, reasoning, and task definition. Claude Code is primarily used for repository-side implementation, testing, and committing changes. These are roles, not authority levels: both agents must verify the repository before making claims about current implementation.

## Synchronization boundary

GitHub is the synchronization boundary. A decision becomes actionable for Claude Code when it is represented in a repository document, task contract, or code change.

## Human role

The human chooses goals and approves work. The human should not be required to manually relay large technical context between the two agents when that context can be stored in Git.

## Conflict handling

If ChatGPT says X but the repository says Y, Claude Code must inspect the repository and history and report the discrepancy. If Claude Code implements X but the resulting code contradicts the repository's accepted architecture, ChatGPT should review the resulting commit and request correction through a new repository task/decision.
