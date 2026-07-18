# 0001: Prefer an evidence chain over status-code-only detection

- Status: Accepted
- Date: 2026-07-19

## Context

An attacker request that returns `2xx` is not sufficient evidence of IDOR. The endpoint may
ignore the identifier, return generic content, or serve the attacker's own object. That makes
status-only automation noisy and unsafe to present as a confirmed finding.

## Decision

Evaluate each candidate with three roles:

1. `attacker-own` establishes that the attacker's baseline is valid.
2. `attacker-mutated` requests the victim identifier using attacker authentication.
3. `victim-control` establishes what the victim's real response looks like.

Score the chain using positive and negative evidence, including response similarity, owner
fields, denial behavior, login/auth responses, generic bodies, and control validity. Require
valid attacker and victim controls plus a successful mutated response before setting
`vulnerable: true`. Optional browser validation may adjust confidence but must not replace the
three-role API evidence model.

## Consequences

- Findings are more explainable and have fewer false positives.
- Users must provide two isolated account contexts and matching identifier pairs.
- Scoring changes need regression cases that cover both true-positive and false-positive
  behavior; changing only a numeric threshold is not enough justification.

## Verification anchors

- `src/idor-engine.ts`
- `src/browser-validator.ts`
- `src/types.ts`
- `test/idor-engine-mutation.test.ts`
