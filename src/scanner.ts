import type { Finding, RequestTemplate, ScanResult, ToolConfig } from "./types.js";
import { loadTemplatesFromOpenApi } from "./openapi.js";
import { runTemplateProbe } from "./idor-engine.js";
import { browserValidateFindings } from "./browser-validator.js";
import { uniqueBy } from "./utils.js";

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
  const collectedTemplates: RequestTemplate[] = [];

  if (config.openApiSpec) {
    const openApiTemplates = await loadTemplatesFromOpenApi(config, cwd);
    if (openApiTemplates.length === 0) {
      notes.push("No IDOR-like candidates were extracted from OpenAPI. Check include/exclude patterns.");
    }
    collectedTemplates.push(...openApiTemplates);
  }

  if (config.targets.length > 0) {
    const targetTemplates = config.targets.map((target) => ({
      method: target.method,
      path: target.path,
      operationId: target.operationId ?? `${target.method.toLowerCase()}_${target.path.replace(/[^a-zA-Z0-9]+/g, "_")}`,
      summary: target.summary,
      pathParams: target.pathParams ?? [],
      queryParams: target.queryParams ?? [],
      bodyKeys: target.bodyKeys ?? []
    }));

    collectedTemplates.push(...targetTemplates);
    notes.push(`Using ${targetTemplates.length} explicit target(s) from config.targets.`);
  }

  const templates = uniqueBy(
    collectedTemplates,
    (template) => `${template.method} ${template.path} ${template.operationId}`
  ).slice(0, config.scan.maxCandidates);

  if (templates.length === 0) {
    notes.push("No request templates available to scan. Provide OpenAPI candidates or config.targets.");
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
