import test from "node:test";
import assert from "node:assert/strict";
import { buildScenarioRequests } from "../src/idor-engine.js";
import type { RequestTemplate, ToolConfig } from "../src/types.js";

function createConfig(): ToolConfig {
  return {
    baseUrl: "https://api.example.com",
    openApiSpec: "unused.json",
    auth: {
      attacker: { headers: { Authorization: "Bearer attacker" } },
      victim: { headers: { Authorization: "Bearer victim" } }
    },
    defaultHeaders: { Accept: "application/json" },
    identifiers: {
      cid: { attacker: "CUST-1", victim: "CUST-2" }
    },
    scan: {
      safeMode: false,
      maxCandidates: 1,
      maxMutationVariants: 6,
      concurrency: 2,
      methods: ["POST"],
      includePaths: [],
      excludePaths: [],
      idParameterPatterns: ["id", "cid"],
      ownerKeywords: ["cid", "customerId"],
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
}

test("buildScenarioRequests mutates pivot/owner fields without blindly mutating unrelated body ids", () => {
  const config = createConfig();

  const template: RequestTemplate = {
    method: "POST",
    path: "/orders",
    operationId: "createOrder",
    pathParams: [],
    queryParams: [],
    bodyKeys: ["cid", "orderLines.productId"]
  };

  const scenario = buildScenarioRequests(template, config);

  assert.deepEqual(scenario.attackerOwn.body, { cid: "CUST-1" });
  assert.deepEqual(scenario.attackerMutated.body, { cid: "CUST-2" });
  assert.deepEqual(scenario.victimControl.body, { cid: "CUST-2" });
});

test("buildScenarioRequests rejects prototype-pollution body keys", () => {
  const config = createConfig();

  const template: RequestTemplate = {
    method: "POST",
    path: "/orders",
    operationId: "createOrder",
    pathParams: [],
    queryParams: [],
    bodyKeys: ["cid", "__proto__.polluted"]
  };

  const scenario = buildScenarioRequests(template, config);
  const globalProbe = {} as Record<string, unknown>;

  assert.deepEqual(scenario.attackerMutated.body, { cid: "CUST-2" });
  assert.equal(globalProbe.polluted, undefined);
});

test("buildScenarioRequests safely handles regex-significant path param names", () => {
  const config = {
    ...createConfig(),
    identifiers: {
      "id(1)": { attacker: "10", victim: "20" }
    }
  };

  const template: RequestTemplate = {
    method: "GET",
    path: "/users/{id(1)}",
    operationId: "getUser",
    pathParams: ["id(1)"],
    queryParams: [],
    bodyKeys: []
  };

  const scenario = buildScenarioRequests(template, config);
  assert.equal(scenario.attackerMutated.url.endsWith("/users/20"), true);
});
