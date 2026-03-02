#!/usr/bin/env node
import process from "node:process";
import { Command } from "commander";
import { loadConfig } from "./config.js";
import { runScan } from "./scanner.js";
import { writeReports } from "./report.js";
import type { Finding, ScanResult } from "./types.js";

function countVulnerable(findings: { vulnerable: boolean }[]): number {
  return findings.filter((finding) => finding.vulnerable).length;
}

function summarizeSeverity(findings: Finding[]): Record<Finding["severity"], number> {
  const summary: Record<Finding["severity"], number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  for (const finding of findings) {
    summary[finding.severity] += 1;
  }

  return summary;
}

function durationMs(startedAt: string, finishedAt: string): number {
  const started = Date.parse(startedAt);
  const finished = Date.parse(finishedAt);
  if (Number.isNaN(started) || Number.isNaN(finished)) {
    return 0;
  }
  return Math.max(0, finished - started);
}

function useColorOutput(colorOption: boolean): boolean {
  if (!colorOption) {
    return false;
  }
  if ("NO_COLOR" in process.env) {
    return false;
  }
  if (process.env.FORCE_COLOR === "0") {
    return false;
  }
  if (process.env.FORCE_COLOR) {
    return true;
  }
  return Boolean(process.stdout.isTTY);
}

function paint(text: string, colorCode: string, enabled: boolean): string {
  if (!enabled) {
    return text;
  }
  return `${colorCode}${text}\x1b[0m`;
}

function tag(label: string, colorCode: string, enabled: boolean): string {
  return paint(`[${label}]`, colorCode, enabled);
}

function printHumanSummary(
  result: ScanResult,
  reportPaths: { jsonPath: string; markdownPath: string },
  options: { verbose: boolean; color: boolean }
): number {
  const enabledColor = useColorOutput(options.color);
  const vulnerableCount = countVulnerable(result.findings);
  const severity = summarizeSeverity(result.findings);
  const elapsed = durationMs(result.startedAt, result.finishedAt);

  const statusTag = vulnerableCount > 0 ? tag("VULN", "\x1b[33m", enabledColor) : tag("OK", "\x1b[32m", enabledColor);
  const scanTag = tag("SCAN", "\x1b[36m", enabledColor);
  const infoTag = tag("INFO", "\x1b[36m", enabledColor);
  const noteTag = tag("NOTE", "\x1b[33m", enabledColor);
  const reportTag = tag("REPORT", "\x1b[35m", enabledColor);

  console.log(`${scanTag} Completed in ${elapsed} ms`);
  console.log(`${statusTag} candidates=${result.candidateCount} executed=${result.executedCount} vulnerable=${vulnerableCount}`);
  console.log(
    `${infoTag} severity critical=${severity.critical} high=${severity.high} medium=${severity.medium} low=${severity.low} info=${severity.info}`
  );

  if (result.notes.length > 0) {
    for (const note of result.notes) {
      console.log(`${noteTag} ${note}`);
    }
  }

  if (options.verbose) {
    const topVulns = [...result.findings]
      .filter((finding) => finding.vulnerable)
      .sort((a, b) => b.confidence - a.confidence)
      .slice(0, 5);

    if (topVulns.length > 0) {
      console.log(`${infoTag} Top vulnerable findings:`);
      for (const finding of topVulns) {
        console.log(`  - ${finding.id} ${finding.method} ${finding.path} (confidence=${finding.confidence})`);
      }
    }
  }

  console.log(`${reportTag} JSON: ${reportPaths.jsonPath}`);
  console.log(`${reportTag} Markdown: ${reportPaths.markdownPath}`);

  return vulnerableCount;
}

function printJsonSummary(result: ScanResult, reportPaths: { jsonPath: string; markdownPath: string }): number {
  const vulnerableCount = countVulnerable(result.findings);
  const severity = summarizeSeverity(result.findings);
  const elapsed = durationMs(result.startedAt, result.finishedAt);
  const exitCode = vulnerableCount > 0 ? 2 : 0;

  const payload = {
    status: vulnerableCount > 0 ? "vulnerable" : "clean",
    exitCode,
    elapsedMs: elapsed,
    summary: {
      candidateCount: result.candidateCount,
      executedCount: result.executedCount,
      vulnerableCount,
      severity,
      notes: result.notes
    },
    reports: reportPaths
  };

  console.log(JSON.stringify(payload, null, 2));
  return vulnerableCount;
}

type ScanCliOptions = {
  config: string;
  verbose: boolean;
  json: boolean;
  color: boolean;
};

const program = new Command();
program
  .name("idor-scout")
  .description("High-confidence IDOR scanner using OpenAPI seeds + dual-account + Playwright validation")
  .version("0.1.0");
program.showHelpAfterError();
program.showSuggestionAfterError(true);
program.addHelpText(
  "after",
  `
Examples:
  $ idor-scout scan -c config.json
  $ idor-scout scan -c config.json --verbose
  $ idor-scout scan -c config.json --json --no-color

Exit codes:
  0 no high-confidence issue found
  1 runtime/config error
  2 at least one finding detected
`
);

const scanCommand = program
  .command("scan")
  .description("Run IDOR scan")
  .requiredOption("-c, --config <path>", "Path to JSON config")
  .option("--verbose", "Print additional runtime details")
  .option("--json", "Print summary in JSON format")
  .option("--no-color", "Disable ANSI colors in output")
  .showHelpAfterError()
  .showSuggestionAfterError(true)
  .addHelpText(
    "after",
    `
Examples:
  $ idor-scout scan -c config.json
  $ idor-scout scan -c config.json --verbose
  $ idor-scout scan -c config.json --json
`
  )
  .action(async (options: ScanCliOptions) => {
    try {
      const cwd = process.cwd();
      const { config, absolutePath } = await loadConfig(options.config);

      if (options.verbose && !options.json) {
        const infoTag = tag("INFO", "\x1b[36m", useColorOutput(options.color));
        console.log(`${infoTag} Config: ${absolutePath}`);
        console.log(`${infoTag} Base URL: ${config.baseUrl}`);
        console.log(`${infoTag} OpenAPI: ${config.openApiSpec ?? "(disabled)"}`);
        console.log(`${infoTag} Explicit targets: ${config.targets.length}`);
        console.log(`${infoTag} Output dir: ${config.outputDir}`);
      }

      const result = await runScan(config, cwd);
      const reportPaths = await writeReports(result, config.outputDir);
      const vulnerableCount = options.json
        ? printJsonSummary(result, reportPaths)
        : printHumanSummary(result, reportPaths, { verbose: options.verbose, color: options.color });

      if (vulnerableCount > 0) {
        process.exitCode = 2;
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (options.json) {
        console.error(
          JSON.stringify(
            {
              status: "error",
              exitCode: 1,
              message
            },
            null,
            2
          )
        );
      } else {
        const enabledColor = useColorOutput(options.color);
        const errorTag = tag("ERROR", "\x1b[31m", enabledColor);
        console.error(`${errorTag} Scan failed: ${message}`);
      }
      process.exitCode = 1;
    }
  });

scanCommand.addHelpText(
  "after",
  `
Exit codes:
  0 no high-confidence issue found
  1 runtime/config error
  2 at least one finding detected
`
);

program.parseAsync(process.argv);
