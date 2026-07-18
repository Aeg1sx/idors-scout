---
name: maintain-idor-scout
description: Maintain and extend the IDOR Scout TypeScript CLI while preserving its authorization boundary, safe defaults, two-account evidence model, false-positive controls, redaction, and public CLI/config/report contracts. Use for changes or reviews involving OpenAPI discovery, manual targets, request mutations, confidence scoring, Playwright validation, reports, configuration, tests, or release-facing documentation in this repository.
---

# Maintain IDOR Scout

## Establish context

1. Read `AGENTS.md` from the repository root.
2. Read `docs/decisions/README.md` and only the records relevant to the task.
3. Read [task playbooks](references/task-playbooks.md) for the affected subsystem.
4. Inspect the current source and tests before proposing or making a change.

Treat repository access as permission to edit and test the code, not as permission to scan a
live service. Do not run a non-local scan without the explicit target and authorization required
by `AGENTS.md`.

## Execute the change

1. Classify the change as discovery, scenario construction, scoring, browser validation,
   reporting, configuration, or CLI behavior.
2. Trace the behavior from its public input through the relevant source to its output. Do not
   patch only the visible symptom when the contract originates elsewhere.
3. Identify the applicable decision constraints. If the requested behavior conflicts with one,
   surface the conflict and update the decision only when the task intentionally changes it.
4. Implement the smallest coherent change. Keep security-sensitive behavior explicit and avoid
   hidden fallbacks.
5. Add focused regression coverage. Include a negative case for changes that could increase
   false positives, request scope, or secret exposure.
6. Update examples and both language versions of user documentation for public behavior.
7. Run the narrow test while iterating, then run `npm run check` before handoff.

## Review findings

Prioritize issues that can cause unauthorized requests, false vulnerability claims, leaked
credentials, prototype pollution, unbounded traversal or request growth, or silent public
contract breaks. Cite a concrete path and behavior. Separate a verified defect from a hardening
suggestion.

## Handoff

Report:

- the user-visible result;
- files or contracts changed;
- focused and full verification performed;
- whether live network testing was skipped;
- any remaining uncertainty or compatibility impact.
