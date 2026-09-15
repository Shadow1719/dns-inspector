# AI Handoff Verification

**Purpose:** verify that a repository-side Claude Code instance can discover and correctly interpret the shared AI collaboration protocol without receiving ChatGPT's conversation.

## Instructions for Claude Code

Do not ask the human to paste the ChatGPT conversation.

Read, in order:

1. `AGENTS.md`
2. `CLAUDE.md`
3. `docs/CURRENT_STATE.md`
4. `docs/DECISIONS.md`
5. `docs/ARCHITECTURE.md`

Then inspect the current Git branch and recent history.

Create `docs/AI_HANDOFF_RESULT.md` containing a concise verification report with these exact sections:

## Repository identity

State the repository, branch, and what you consider the authoritative source of project state.

## Two-agent model

Explain, in your own words, how ChatGPT and Claude Code synchronize despite being separate AI instances.

## Authority order

State which wins if conversation memory conflicts with repository code/documentation.

## Implementation contract

Explain what a `READY` task means and whether you are allowed to broaden its scope.

## Verification

List the files you actually read and the current commit SHA you inspected.

## Result

State `PASS` only if you can explain the protocol from repository contents alone. Otherwise state `BLOCKED` and explain exactly what is missing or contradictory.

Do not modify application code for this verification. Do not invent project state.
