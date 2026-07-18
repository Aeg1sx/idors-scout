# Task playbooks

Use the smallest playbook that covers the task. Return to `AGENTS.md` for repository-wide
constraints and `docs/decisions` for rationale.

## Config and target inputs

- Trace raw input through normalization and required-field checks in `src/config.ts`.
- Preserve config-file-relative resolution for OpenAPI specs, storage states, and output.
- Test both accepted input and rejection behavior in `test/config.test.ts`.
- Update `examples/config*.json` and both READMEs when keys, defaults, or modes change.

## OpenAPI discovery

- Keep discovery separate from probing; return `RequestTemplate` values, not findings.
- Account for path-level and operation-level parameters, JSON request bodies, `$ref`, composed
  schemas, arrays, recursive schemas, unsafe object keys, filters, method selection, and caps.
- Add a compact OpenAPI fixture to `test/openapi.test.ts` for every new traversal rule.
- Prove termination for recursive or deeply nested input.

## Scenario construction and mutations

- Preserve distinct authentication for attacker and victim controls.
- Mutate only the pivot, mapped identifier, or ownership-related body fields. Do not rewrite
  unrelated IDs merely because their names contain `id`.
- Defend dotted-key writes against `__proto__`, `prototype`, and `constructor` segments.
- Deduplicate concrete mutations before applying `maxMutationVariants`.
- Use mocked or local deterministic HTTP behavior for end-to-end probe tests.

## Scoring and browser validation

- Start with valid own-resource and victim-control baselines.
- Keep successful mutated status as one signal rather than proof.
- Exercise true-positive, blocked, generic-response, attacker-owned-response, auth-page, and
  network-error cases when changing weights or thresholds.
- Recalculate confidence, `vulnerable`, and severity coherently after browser evidence.
- Keep API-only scanning functional when Playwright is disabled.

## Reports and CLI

- Sanitize request and response copies before JSON or Markdown serialization.
- Test sensitive headers, nested body secrets, JWT-like text, and error strings when changing
  redaction.
- Preserve exit codes: `0` for no high-confidence finding, `1` for runtime/config error, and `2`
  when at least one finding is detected.
- Keep `--json` machine-readable and keep diagnostics off its standard output payload.
- Treat report fields and CLI/config names as public contracts.

## Verification commands

```bash
npm test -- --test-name-pattern='<focused name>'
npm run build
npm run check
```

Do not install Playwright browsers unless the task actually requires browser integration.
