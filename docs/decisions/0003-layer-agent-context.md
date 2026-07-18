# 0003: Layer repository-specific context for agents

- Status: Accepted
- Date: 2026-07-19

## Context

A single long agent prompt is easy to miss, expensive to load, and likely to drift from source.
Source code alone exposes current mechanics but not the trade-offs that future changes must
preserve.

## Decision

Use three repository-owned layers:

- `AGENTS.md` is the short, always-relevant entry point for scope, safety invariants, file
  routing, and the definition of done.
- `.agents/skills/maintain-idor-scout/` contains the reusable implementation workflow and
  task-specific playbooks.
- `docs/decisions/` stores durable rationale and consequences for choices that constrain later
  work.

Keep executable truth in source and tests. Link to those verification anchors from decisions
instead of duplicating constants or function-level behavior in prose. Update the nearest layer
in the same change whenever a project decision or public contract changes.

## Consequences

- Agents can load a small default context and progressively read only relevant detail.
- The files work in normal code review and do not depend on an external memory service.
- Maintainers must treat stale instructions as a defect and review context changes alongside
  code changes.

## Verification anchors

- `AGENTS.md`
- `.agents/skills/maintain-idor-scout/SKILL.md`
- `.agents/skills/maintain-idor-scout/references/task-playbooks.md`
- `package.json`
