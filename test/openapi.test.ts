import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { loadTemplatesFromOpenApi } from "../src/openapi.js";
import type { ToolConfig } from "../src/types.js";

const baseConfig: ToolConfig = {
  baseUrl: "https://api.example.com",
  openApiSpec: "",
  auth: {
    attacker: { headers: { Authorization: "Bearer a" } },
    victim: { headers: { Authorization: "Bearer b" } }
  },
  defaultHeaders: { Accept: "application/json" },
  identifiers: {
    userid: { attacker: "100", victim: "200" }
  },
  scan: {
    safeMode: true,
    maxCandidates: 200,
    maxMutationVariants: 8,
    concurrency: 2,
    methods: ["GET"],
    includePaths: [],
    excludePaths: [],
    idParameterPatterns: ["id", "userId"],
    ownerKeywords: ["ownerId", "userId"],
    timeoutMs: 5000
  },
  playwright: {
    enabled: false,
    headed: false,
    timeoutMs: 10000,
    screenshotOnValidation: false
  },
  outputDir: "output"
};

test("extracts path/query/body id candidates from OpenAPI JSON", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "idor-openapi-test-"));
  try {
    const specPath = path.join(tempDir, "openapi.json");
    const doc = {
      openapi: "3.0.0",
      paths: {
        "/users/{userId}": {
          get: {
            operationId: "getUser",
            parameters: [
              { name: "userId", in: "path", required: true, schema: { type: "string" } },
              { name: "expand", in: "query", schema: { type: "string" } }
            ]
          }
        },
        "/invoices": {
          post: {
            operationId: "createInvoice",
            requestBody: {
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      ownerId: { type: "string" },
                      amount: { type: "number" }
                    }
                  }
                }
              }
            }
          }
        }
      }
    };

    await writeFile(specPath, JSON.stringify(doc), "utf8");

    const templates = await loadTemplatesFromOpenApi(
      {
        ...baseConfig,
        openApiSpec: specPath,
        scan: {
          ...baseConfig.scan,
          safeMode: false,
          methods: ["GET", "POST"]
        }
      },
      process.cwd()
    );

    assert.equal(templates.length, 2);

    const userTemplate = templates.find((template) => template.operationId === "getUser");
    assert.ok(userTemplate);
    assert.deepEqual(userTemplate.pathParams, ["userId"]);

    const invoiceTemplate = templates.find((template) => template.operationId === "createInvoice");
    assert.ok(invoiceTemplate);
    assert.deepEqual(invoiceTemplate.bodyKeys, ["ownerId"]);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("handles recursive OpenAPI schemas without infinite recursion", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "idor-openapi-recursive-test-"));
  try {
    const specPath = path.join(tempDir, "openapi.json");
    const doc = {
      openapi: "3.0.0",
      paths: {
        "/tree": {
          post: {
            operationId: "createTree",
            requestBody: {
              content: {
                "application/json": {
                  schema: {
                    $ref: "#/components/schemas/Node"
                  }
                }
              }
            }
          }
        }
      },
      components: {
        schemas: {
          Node: {
            type: "object",
            properties: {
              nodeId: { type: "string" },
              child: { $ref: "#/components/schemas/Node" }
            }
          }
        }
      }
    };

    await writeFile(specPath, JSON.stringify(doc), "utf8");

    const templates = await loadTemplatesFromOpenApi(
      {
        ...baseConfig,
        openApiSpec: specPath,
        scan: {
          ...baseConfig.scan,
          safeMode: false,
          methods: ["POST"]
        }
      },
      process.cwd()
    );

    assert.equal(templates.length, 1);
    assert.equal(templates[0].operationId, "createTree");
    assert.equal(templates[0].bodyKeys.includes("nodeId"), true);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});
