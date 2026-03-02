import type { Finding, RequestTemplate, ScanResult, ToolConfig } from "./types.js";
import { loadTemplatesFromOpenApi } from "./openapi.js";
import { runTemplateProbe } from "./idor-engine.js";
import { browserValidateFindings } from "./browser-validator.js";

function recalculateSeverity(finding: Finding): Finding["severity"] {
  if (!finding.vulnerable) {
    return finding.confidence >= 35 ? "low" : "info";
  }

  if (finding.confidence >= 90) {
    return "critical";
  }
  if (finding.confidence >= 75) {
    return "high";
  }
  if (finding.confidence >= 60) {
    return "medium";
  }
  return "low";
}

async function runWithConcurrency<TInput, TOutput>(
  items: TInput[],
  limit: number,
  worker: (item: TInput, index: number) => Promise<TOutput>
): Promise<TOutput[]> {
  const results: TOutput[] = new Array(items.length);
  let cursor = 0;

  async function runOne(): Promise<void> {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      const item = items[index];
      if (item === undefined) {
        break;
      }
      results[index] = await worker(item, index);
    }
  }

  const workers = new Array(Math.max(1, Math.min(limit, items.length))).fill(null).map(() => runOne());
  await Promise.all(workers);
  return results;
}

export async function runScan(config: ToolConfig, cwd: string): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const notes: string[] = [];

  const templates = await loadTemplatesFromOpenApi(config, cwd);
  if (templates.length === 0) {
    notes.push("No IDOR-like candidates were extracted from OpenAPI. Check include/exclude patterns.");
  }

  const findings = await runWithConcurrency<RequestTemplate, Finding>(templates, config.scan.concurrency, async (template) => {
    return await runTemplateProbe(template, config);
  });

  const browserChecked = await browserValidateFindings(findings, config, config.outputDir);
  for (const finding of browserChecked) {
    finding.severity = recalculateSeverity(finding);
  }

  const finishedAt = new Date().toISOString();

  return {
    startedAt,
    finishedAt,
    candidateCount: templates.length,
    executedCount: findings.length,
    findings: browserChecked,
    notes
  };
}
