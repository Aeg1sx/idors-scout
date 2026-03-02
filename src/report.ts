import path from "node:path";
import { mkdir, writeFile } from "node:fs/promises";
import type { ConcreteRequest, Finding, ProbeResponse, ScanResult } from "./types.js";
import { sanitizeSnippet } from "./utils.js";

type SummaryCounts = {
  vulnerable: number;
} & Record<Finding["severity"], number>;

function findingOrder(a: Finding, b: Finding): number {
  return b.confidence - a.confidence;
}

const SENSITIVE_HEADER_KEY = /authorization|cookie|set-cookie|x-api-key|api-key|token|secret/i;
const SENSITIVE_BODY_KEY = /password|passwd|token|secret|authorization|cookie|api[-_]?key/i;
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;

function redactTokenLike(text: string): string {
  return text.replace(JWT_PATTERN, "[REDACTED_JWT]");
}

function redactHeaderValue(key: string, value: string): string {
  if (!SENSITIVE_HEADER_KEY.test(key)) {
    return redactTokenLike(value);
  }
  if (key.toLowerCase() === "authorization") {
    const [scheme] = value.split(/\s+/, 1);
    return scheme ? `${scheme} [REDACTED]` : "[REDACTED]";
  }
  return "[REDACTED]";
}

function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    out[key] = redactHeaderValue(key, value);
  }
  return out;
}

function redactBody(value: unknown): unknown {
  if (!value || typeof value !== "object") {
    return typeof value === "string" ? redactTokenLike(value) : value;
  }

  if (Array.isArray(value)) {
    return value.map(redactBody);
  }

  const out: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (SENSITIVE_BODY_KEY.test(key)) {
      out[key] = "[REDACTED]";
      continue;
    }
    out[key] = redactBody(child);
  }
  return out;
}

function sanitizeRequest(request: ConcreteRequest): ConcreteRequest {
  return {
    ...request,
    headers: redactHeaders(request.headers),
    body: redactBody(request.body)
  };
}

function sanitizeResponse(response: ProbeResponse): ProbeResponse {
  return {
    ...response,
    headers: redactHeaders(response.headers),
    text: redactTokenLike(response.text),
    json: redactBody(response.json),
    error: response.error ? redactTokenLike(response.error) : response.error
  };
}

function sanitizeFinding(finding: Finding): Finding {
  return {
    ...finding,
    requests: {
      attackerOwn: sanitizeRequest(finding.requests.attackerOwn),
      attackerMutated: sanitizeRequest(finding.requests.attackerMutated),
      victimControl: sanitizeRequest(finding.requests.victimControl)
    },
    responses: {
      attackerOwn: sanitizeResponse(finding.responses.attackerOwn),
      attackerMutated: sanitizeResponse(finding.responses.attackerMutated),
      victimControl: sanitizeResponse(finding.responses.victimControl)
    }
  };
}

function summaryCounts(findings: Finding[]): SummaryCounts {
  const out: SummaryCounts = {
    vulnerable: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  for (const finding of findings) {
    if (finding.vulnerable) {
      out.vulnerable += 1;
    }
    out[finding.severity] += 1;
  }

  return out;
}

function findingSection(finding: Finding): string {
  const evidence = finding.evidence
    .map((item) => `- (${item.scoreImpact >= 0 ? "+" : ""}${item.scoreImpact}) ${item.reason}`)
    .join("\n");

  return [
    `### ${finding.id} - ${finding.method} ${finding.path}`,
    `- Operation: ${finding.operationId}`,
    `- Mutation variant: ${finding.mutationVariant}`,
    `- Severity: ${finding.severity}`,
    `- Confidence: ${finding.confidence}`,
    `- Vulnerable: ${finding.vulnerable ? "yes" : "no"}`,
    `- Browser validated: ${finding.browserValidated ? "yes" : "no"}`,
    `- Variant score snapshot: ${finding.variantScores
      .slice(0, 5)
      .map((variant) => `${variant.name}(${variant.status}/${variant.confidence})`)
      .join(", ")}`,
    "- Evidence:",
    evidence || "- (none)",
    "- Mutated response snippet:",
    "```",
    sanitizeSnippet(finding.responses.attackerMutated.text, 400),
    "```"
  ].join("\n");
}

export async function writeReports(result: ScanResult, outputDir: string): Promise<{ jsonPath: string; markdownPath: string }> {
  await mkdir(outputDir, { recursive: true });

  const sorted = [...result.findings].map(sanitizeFinding).sort(findingOrder);
  const normalized: ScanResult = {
    ...result,
    findings: sorted
  };

  const jsonPath = path.join(outputDir, "idor-report.json");
  const markdownPath = path.join(outputDir, "idor-report.md");

  const counts = summaryCounts(sorted);
  const markdown = [
    "# IDOR Scout Report",
    "",
    `- Started: ${normalized.startedAt}`,
    `- Finished: ${normalized.finishedAt}`,
    `- Candidates: ${normalized.candidateCount}`,
    `- Executed: ${normalized.executedCount}`,
    `- Vulnerable findings: ${counts.vulnerable}`,
    "",
    "## Severity",
    "",
    `- Critical: ${counts.critical}`,
    `- High: ${counts.high}`,
    `- Medium: ${counts.medium}`,
    `- Low: ${counts.low}`,
    `- Info: ${counts.info}`,
    "",
    "## Notes",
    "",
    ...(normalized.notes.length > 0 ? normalized.notes.map((note) => `- ${note}`) : ["- none"]),
    "",
    "## Findings",
    "",
    ...(sorted.length > 0 ? sorted.map(findingSection) : ["No findings."])
  ].join("\n");

  await Promise.all([
    writeFile(jsonPath, JSON.stringify(normalized, null, 2), "utf8"),
    writeFile(markdownPath, markdown, "utf8")
  ]);

  return { jsonPath, markdownPath };
}
