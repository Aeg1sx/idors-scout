# IDOR Scout agent guide

These instructions apply to the entire repository.

## Start here

1. Read `README.md` for the supported user-facing behavior.
2. Read `docs/decisions/README.md` and the decision records relevant to the change.
3. For implementation work, use the repository skill at
   `.agents/skills/maintain-idor-scout/SKILL.md`.

## Safety boundary

- Work only on systems the user is explicitly authorized to test.
- Treat repository access, a sample config, or a URL in documentation as insufficient
  authorization to run a live scan.
- Do not run `idor-scout scan` against a non-local target unless the user explicitly asks
  for that target to be tested and confirms authorization.
- Never add real credentials, cookies, storage states, customer identifiers, or raw tokens
  to source, tests, fixtures, logs, or reports.
- Preserve `scan.safeMode: true` and GET-only discovery as the default. Relaxing a safety
  default requires an explicit task, regression tests, documentation, and a decision-record
  update.

## Architectural invariants

- Candidate discovery is not vulnerability proof. A high-confidence result requires the
  `attacker-own`, `attacker-mutated`, and `victim-control` evidence chain.
- A successful status code alone must not establish an IDOR finding. Keep negative signals,
  response comparison, ownership evidence, and control validity in the score.
- Keep mutations bounded by configured candidate, variant, concurrency, method, path, and
  timeout limits.
- Browser validation is optional corroboration. API-only operation must continue to work.
- Reports must sanitize copies of requests and responses. Never weaken redaction to improve
  report detail.
- Resolve config-relative files from the config file's directory, not the caller's current
  directory.
- Avoid breaking CLI flags, exit codes, config keys, and report fields without migration
  notes and tests.

## Change map

| Change | Primary code | Minimum focused verification |
| --- | --- | --- |
| Config/defaults/manual targets | `src/config.ts`, `src/types.ts` | `test/config.test.ts` |
| OpenAPI candidate extraction | `src/openapi.ts` | `test/openapi.test.ts` |
| Scenario construction/mutations/scoring | `src/idor-engine.ts` | `test/idor-engine-mutation.test.ts` plus a new scoring regression when applicable |
| Scan orchestration/browser checks | `src/scanner.ts`, `src/browser-validator.ts` | Add or update an orchestration/browser test |
| Report format/redaction | `src/report.ts` | `test/report-redaction.test.ts` |
| CLI contract | `src/cli.ts` | Build, help/output check, and a CLI regression test for behavior changes |

## Definition of done

- Add or update tests for behavior changes.
- Update both English and Korean user documentation when public behavior changes.
- Run `npm run check`.
- State what was tested and whether any live network action was intentionally skipped.

## Keep decisions available to future agents

Use `docs/decisions` for durable choices that constrain later work, especially changes to
safety defaults, the evidence model, public compatibility, or secret handling. Update an
existing record when the original decision evolves; add a new record when the context and
trade-offs are materially different. Link decisions to source and tests instead of copying
implementation details into this file.
