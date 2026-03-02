# IDOR Scout

English | [한국어](README.ko.md)

`IDOR Scout` is a CLI tool designed to reduce false positives in IDOR (Insecure Direct Object Reference) testing by combining OpenAPI(JSON)-driven target discovery, two-account cross-validation, and optional Playwright browser-context revalidation.

## Why This Architecture

Instead of relying on status-code-only checks, IDOR Scout uses an evidence-chain scoring model that combines multiple signals from API responses and browser-level validation.

## Core Features

- Automatic IDOR candidate extraction from OpenAPI(JSON)
  - Detects ID-like fields in path/query/body
  - Supports `$ref` schema traversal
- Two-account cross-validation
  - `attacker-own`
  - `attacker-mutated(victim id)`
  - `victim-control`
- Bypass mutation set (practical IDOR patterns)
  - Path variants: trailing slash, double slash, version downgrade, endpoint sibling
  - ID payload variants: multi-id comma/dot, leading-zero, quoted numeric, encoded space, null-byte
  - Request variants: method swap, `X-Original-URL`, `X-Forwarded-For`
- False-positive suppression scoring
  - Combines status code, body similarity, owner field checks, and response stability
  - Penalizes login HTML, auth redirects, and explicit access-denied messages
- Safe report output
  - Auto-masks `Authorization`, `Cookie`, `X-Api-Key`, JWT/secret/password patterns
- Playwright browser-context revalidation
  - Re-checks findings with real authenticated storage states (cookie/session)
- Output reports
  - `output/idor-report.json`
  - `output/idor-report.md`

## Distribution Status

- This project is currently not published to npm.
- Use it from source via GitHub clone + local build.

## Installation (From Source)

```bash
git clone https://github.com/<your-org-or-user>/idors-scout.git
cd idors-scout
npm install
npx playwright install chromium
npm run build
```

## Local CLI Usage

```bash
node dist/cli.js --help
```

## Quick Start

1. Copy example config

```bash
cp examples/config.example.json config.json
```

2. Update `config.json`

- `baseUrl`, `openApiSpec`
- `auth.attacker.headers.Authorization`
- `auth.victim.headers.Authorization`
- `identifiers` (attacker/victim ID pairs)

3. Run scan

```bash
node dist/cli.js scan -c config.json
```

For development mode (without prebuild):

```bash
npm run dev -- scan -c config.json
```

CLI options:
- `--verbose`: prints additional runtime details
- `--json`: prints machine-readable summary JSON to stdout
- `--no-color`: disables ANSI color output

Exit codes:
- `0`: no high-confidence issue found
- `1`: runtime/config error
- `2`: at least one finding detected

## Enable Playwright Revalidation

In `config.json`:

- `playwright.enabled: true`
- `playwright.attackerStorageState`
- `playwright.victimStorageState`

Prepare each `storageState` file after login (example):

```ts
import { chromium } from "playwright";

const browser = await chromium.launch({ headless: false });
const context = await browser.newContext();
const page = await context.newPage();
await page.goto("https://app.target.local/login");
// After manual or scripted login
await context.storageState({ path: "attacker.storage.json" });
await browser.close();
```

Create a separate state file for the victim account.

## OpenAPI Support Scope

- Input: JSON file path or URL
- Methods: `GET/POST/PUT/PATCH/DELETE` (defaults to `GET` in safe mode)
- Candidate detection:
  - Path params like `{userId}`, `{projectId}`
  - Query params like `?userId=...`
  - Body keys like `ownerId`, `userId`

## False-Positive Reduction Strategy

- Strong negative weighting when `attacker-mutated` returns `401/403/404`
- Positive weighting when mutated attacker response matches `victim-control` and differs from `attacker-own`
- Extra signal from owner-related field values matching victim identifiers
- Penalizes generic/empty responses
- Lowers confidence when Playwright revalidation disagrees with API-only result
- Limits body mutation scope to pivot/owner/identifier mappings

## Project Structure

- `src/cli.ts`: CLI entrypoint
- `src/config.ts`: config loading and validation
- `src/openapi.ts`: OpenAPI candidate extraction
- `src/idor-engine.ts`: API-level IDOR validation engine
- `src/browser-validator.ts`: Playwright revalidation
- `src/report.ts`: JSON/Markdown reporting

## Testing

```bash
npm test
```

## Maintainer Release Check (Optional)

```bash
npm run publish:check
```

GitHub Actions:
- `.github/workflows/ci.yml` (Node 22/24 build+test)
- `.github/workflows/publish-check.yml` (publish dry-run for maintainers)

## Documentation

- Contribution guide: `CONTRIBUTING.md` / `CONTRIBUTING.ko.md`
- Security policy: `SECURITY.md` / `SECURITY.ko.md`

## Safety Notes

- Test only within explicitly authorized scope.
- `safeMode: true` is recommended (default).
- Limit mutation attempts via `scan.maxMutationVariants` (default: 12).
- Control concurrent requests via `scan.concurrency` (default: 4).
- Prepare rate limits and dedicated test accounts for real environments.
