# Project decisions

This directory records the project-specific choices that an agent or contributor needs in
order to change IDOR Scout without rediscovering its safety and accuracy constraints.

## Index

| ID | Status | Decision |
| --- | --- | --- |
| [0001](0001-evidence-chain-over-status-codes.md) | Accepted | Require a two-account evidence chain instead of status-code-only detection |
| [0002](0002-safe-and-bounded-by-default.md) | Accepted | Keep discovery safe and request generation bounded by default |
| [0003](0003-layer-agent-context.md) | Accepted | Layer agent instructions, reusable workflow, and decision records |

## When to update this directory

Record a decision when it changes or constrains one of these areas:

- authorization or safe execution defaults;
- candidate discovery, mutation, scoring, or validation semantics;
- CLI/config/report compatibility;
- credential and evidence handling;
- repository-wide agent workflow.

Do not record ordinary implementation details that are clear from source and tests.

## Record format

Use the next four-digit number and include:

```markdown
# NNNN: Short decision title

- Status: Proposed | Accepted | Superseded by NNNN
- Date: YYYY-MM-DD

## Context

Why a durable choice is needed.

## Decision

The choice and its non-negotiable boundaries.

## Consequences

Benefits, costs, and follow-up constraints.

## Verification anchors

- `path/to/source`
- `path/to/test`
```
