import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { writeReports } from "../src/report.js";
import type { ScanResult } from "../src/types.js";

const JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.sgn";

test("writeReports redacts sensitive headers/body and JWT-like content", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "idor-report-redaction-"));

  const sample: ScanResult = {
    startedAt: new Date(0).toISOString(),
    finishedAt: new Date(1000).toISOString(),
    candidateCount: 1,
    executedCount: 1,
    notes: [],
    findings: [
      {
        id: "finding-1",
        operationId: "getOrder",
        method: "GET",
        path: "/orders/{id}",
        mutationVariant: "direct-id-swap",
        severity: "high",
        confidence: 80,
        vulnerable: true,
        browserValidated: false,
        evidence: [{ reason: "test", scoreImpact: 10 }],
        variantScores: [{ name: "direct-id-swap", status: 200, confidence: 80 }],
        requests: {
          attackerOwn: {
            method: "GET",
            url: "https://api.example.com/orders/1",
            headers: {
              Authorization: `Bearer ${JWT}`,
              "X-Api-Key": "very-secret",
              Accept: "application/json"
            },
            body: {
              password: "p@ss",
              profile: {
                accessToken: JWT
              }
            }
          },
          attackerMutated: {
            method: "GET",
            url: "https://api.example.com/orders/2",
            headers: {
              Authorization: `Bearer ${JWT}`,
              Cookie: "session=abc"
            },
            body: {
              token: JWT
            }
          },
          victimControl: {
            method: "GET",
            url: "https://api.example.com/orders/2",
            headers: {
              Authorization: `Bearer ${JWT}`
            }
          }
        },
        responses: {
          attackerOwn: {
            status: 200,
            headers: {
              "set-cookie": "sid=123",
              "content-type": "application/json"
            },
            text: `jwt=${JWT}`,
            json: {
              apiKey: "api-secret"
            },
            elapsedMs: 10
          },
          attackerMutated: {
            status: 200,
            headers: {
              "content-type": "application/json"
            },
            text: `token=${JWT}`,
            json: {
              secret: "hidden"
            },
            elapsedMs: 11
          },
          victimControl: {
            status: 200,
            headers: {
              "content-type": "application/json"
            },
            text: "ok",
            elapsedMs: 12
          }
        }
      }
    ]
  };

  try {
    const { jsonPath, markdownPath } = await writeReports(sample, tempDir);
    const jsonText = await readFile(jsonPath, "utf8");
    const markdownText = await readFile(markdownPath, "utf8");

    assert.equal(jsonText.includes(JWT), false);
    assert.equal(markdownText.includes(JWT), false);
    assert.equal(jsonText.includes("very-secret"), false);
    assert.equal(jsonText.includes("api-secret"), false);
    assert.equal(jsonText.includes("p@ss"), false);

    const parsed = JSON.parse(jsonText) as ScanResult;
    const finding = parsed.findings[0];
    assert.equal(finding.requests.attackerOwn.headers.Authorization, "Bearer [REDACTED]");
    assert.equal(finding.requests.attackerOwn.headers["X-Api-Key"], "[REDACTED]");
    assert.equal(finding.responses.attackerOwn.headers["set-cookie"], "[REDACTED]");
    assert.equal(finding.responses.attackerMutated.text.includes("[REDACTED_JWT]"), true);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});
