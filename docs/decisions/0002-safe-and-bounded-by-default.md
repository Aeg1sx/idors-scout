# 0002: Keep scans safe and bounded by default

- Status: Accepted
- Date: 2026-07-19

## Context

IDOR testing sends authenticated requests and may target state-changing operations. Automated
discovery can also expand a small OpenAPI document into many candidate and mutation requests.
The default behavior therefore needs to limit impact even when a config omits tuning options.

## Decision

- Default `scan.safeMode` to `true` and discovery methods to `GET`.
- When safe mode is enabled, discard non-GET methods even if they are requested in config.
- Bound candidates, mutations per candidate, concurrency, and request duration with explicit
  defaults.
- Keep health, metrics, status, and documentation paths excluded by default.
- Require both authenticated account contexts and at least one attacker/victim identifier pair
  before scanning.
- Treat a live target as authorized only when the user explicitly provides that scope and asks
  for the scan. Development and CI verification must use deterministic local fixtures or mocks.

## Consequences

- Source-mode setup remains conservative without requiring expert configuration.
- Broader methods and larger budgets remain possible only through deliberate configuration.
- Changes that increase request reach or volume must update config tests, both READMEs, and this
  record.

## Verification anchors

- `src/config.ts`
- `src/openapi.ts`
- `src/scanner.ts`
- `test/config.test.ts`
- `test/openapi.test.ts`
