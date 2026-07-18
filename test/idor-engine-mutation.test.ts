import test from "node:test";
import assert from "node:assert/strict";
import { buildScenarioRequests, scoreFinding } from "../src/idor-engine.js";
import type { ProbeResponse, RequestTemplate, ToolConfig } from "../src/types.js";

function createConfig(): ToolConfig {
  return {
    baseUrl: "https://api.example.com",
    openApiSpec: "unused.json",
    targets: [],
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

test("scoreFinding does not confirm a finding when the attacker-own baseline fails", () => {
  const base = createConfig();
  const config: ToolConfig = {
    ...base,
    scan: {
      ...base.scan,
      methods: ["GET"]
    }
  };
  const template: RequestTemplate = {
    method: "GET",
    path: "/users/{cid}",
    operationId: "getUser",
    pathParams: ["cid"],
    queryParams: [],
    bodyKeys: []
  };
  const scenario = buildScenarioRequests(template, config);
  const response = (status: number, json: unknown): ProbeResponse => ({
    status,
    headers: { "content-type": "application/json" },
    text: JSON.stringify(json),
    json,
    elapsedMs: 1
  });
  const scored = scoreFinding(
    template,
    scenario,
    {
      attackerOwn: response(500, { error: "baseline unavailable" }),
      attackerMutated: response(200, { cid: "CUST-2", value: "victim data" }),
      victimControl: response(200, { cid: "CUST-2", value: "victim data" })
    },
    config,
    "direct-id-swap",
    200
  );

  assert.ok(scored.confidence >= 60);
  assert.equal(scored.vulnerable, false);
});
