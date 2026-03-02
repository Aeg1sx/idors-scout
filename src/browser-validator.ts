import path from "node:path";
import { mkdir } from "node:fs/promises";
import { chromium, type APIRequestContext, type Browser, type BrowserContext } from "playwright";
import type { Evidence, Finding, ProbeResponse, ToolConfig } from "./types.js";
import { sanitizeSnippet, serializeComparable, similarityRatio, tryParseJson } from "./utils.js";

const BLOCKED = new Set([401, 403, 404]);

function isSuccess(status: number): boolean {
  return status >= 200 && status <= 299;
}

function pushEvidence(evidence: Evidence[], reason: string, scoreImpact: number): void {
  evidence.push({ reason, scoreImpact });
}

async function toProbeResponse(responsePromise: Promise<import("playwright").APIResponse>): Promise<ProbeResponse> {
  const started = Date.now();
  try {
    const response = await responsePromise;
    const text = await response.text();
    return {
      status: response.status(),
      headers: response.headers(),
      text,
      json: tryParseJson(text),
      elapsedMs: Date.now() - started
    };
  } catch (error) {
    return {
      status: 0,
      headers: {},
      text: "",
      elapsedMs: Date.now() - started,
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

async function fetchViaContext(request: APIRequestContext, finding: Finding, useMutated: boolean): Promise<ProbeResponse> {
  const req = useMutated ? finding.requests.attackerMutated : finding.requests.victimControl;
  return toProbeResponse(
    request.fetch(req.url, {
      method: req.method,
      headers: req.headers,
      data: req.body,
      timeout: 15000
    })
  );
}

async function maybeCaptureSmoke(
  attackerContext: BrowserContext,
  victimContext: BrowserContext,
  outputDir: string,
  smokePath: string
): Promise<void> {
  const attackerPage = await attackerContext.newPage();
  const victimPage = await victimContext.newPage();
  try {
    await Promise.all([
      attackerPage.goto(smokePath, { waitUntil: "domcontentloaded", timeout: 20000 }),
      victimPage.goto(smokePath, { waitUntil: "domcontentloaded", timeout: 20000 })
    ]);

    await attackerPage.screenshot({ path: path.join(outputDir, "attacker-smoke.png"), fullPage: true });
    await victimPage.screenshot({ path: path.join(outputDir, "victim-smoke.png"), fullPage: true });
  } finally {
    await Promise.all([attackerPage.close(), victimPage.close()]);
  }
}

async function initContexts(config: ToolConfig): Promise<{
  browser: Browser;
  attackerContext: BrowserContext;
  victimContext: BrowserContext;
}> {
  const browser = await chromium.launch({ headless: !config.playwright.headed });
  const attackerContext = await browser.newContext({
    storageState: config.playwright.attackerStorageState,
    baseURL: config.playwright.baseUrl
  });
  const victimContext = await browser.newContext({
    storageState: config.playwright.victimStorageState,
    baseURL: config.playwright.baseUrl
  });

  return { browser, attackerContext, victimContext };
}

export async function browserValidateFindings(findings: Finding[], config: ToolConfig, outputDir: string): Promise<Finding[]> {
  if (!config.playwright.enabled || findings.length === 0) {
    return findings;
  }

  const targetFindings = findings.filter(
    (finding) => finding.confidence >= 45 && finding.responses.attackerMutated.status >= 200
  );

  if (targetFindings.length === 0) {
    return findings;
  }

  const artifactDir = path.join(outputDir, "playwright");
  await mkdir(artifactDir, { recursive: true });

  const { browser, attackerContext, victimContext } = await initContexts(config);

  try {
    if (config.playwright.smokePath) {
      await maybeCaptureSmoke(attackerContext, victimContext, artifactDir, config.playwright.smokePath);
    }

    const attackerRequest = attackerContext.request;
    const victimRequest = victimContext.request;

    for (const finding of targetFindings) {
      const [attackerMutated, victimControl] = await Promise.all([
        fetchViaContext(attackerRequest, finding, true),
        fetchViaContext(victimRequest, finding, false)
      ]);

      if (attackerMutated.error || victimControl.error) {
        pushEvidence(finding.evidence, "Playwright validation failed due to request errors.", -10);
        finding.confidence = Math.max(0, finding.confidence - 10);
        continue;
      }

      if (BLOCKED.has(attackerMutated.status)) {
        pushEvidence(
          finding.evidence,
          `Playwright context confirms mutated request is blocked (${attackerMutated.status}).`,
          -20
        );
        finding.confidence = Math.max(0, finding.confidence - 20);
        finding.vulnerable = false;
        finding.browserValidated = true;
        continue;
      }

      const attackComparable = attackerMutated.json
        ? serializeComparable(attackerMutated.json)
        : sanitizeSnippet(attackerMutated.text, 2000);
      const victimComparable = victimControl.json
        ? serializeComparable(victimControl.json)
        : sanitizeSnippet(victimControl.text, 2000);
      const similarity = similarityRatio(attackComparable, victimComparable);

      if (isSuccess(attackerMutated.status) && isSuccess(victimControl.status) && similarity > 0.7) {
        pushEvidence(
          finding.evidence,
          `Playwright auth-context replay matched victim control (similarity ${similarity.toFixed(2)}).`,
          15
        );
        finding.confidence = Math.min(100, finding.confidence + 15);
        finding.browserValidated = true;
        finding.vulnerable = finding.confidence >= 60;
      } else {
        pushEvidence(
          finding.evidence,
          `Playwright replay mismatch reduced confidence (status ${attackerMutated.status}/${victimControl.status}, similarity ${similarity.toFixed(2)}).`,
          -10
        );
        finding.confidence = Math.max(0, finding.confidence - 10);
        finding.browserValidated = true;
        finding.vulnerable = finding.confidence >= 60;
      }

      if (config.playwright.screenshotOnValidation && config.playwright.smokePath) {
        const page = await attackerContext.newPage();
        try {
          await page.goto(config.playwright.smokePath, { waitUntil: "domcontentloaded", timeout: 20000 });
          await page.screenshot({
            path: path.join(artifactDir, `${finding.id}.png`),
            fullPage: true
          });
        } catch {
          // Artifact capture is best-effort.
        } finally {
          await page.close();
        }
      }
    }
  } finally {
    await Promise.all([attackerContext.close(), victimContext.close()]);
    await browser.close();
  }

  return findings;
}
