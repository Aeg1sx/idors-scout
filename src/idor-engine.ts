import type {
  ConcreteRequest,
  Evidence,
  Finding,
  IdentifierPair,
  ProbeResponse,
  RequestTemplate,
  ToolConfig
} from "./types.js";
import { executeHttpRequest } from "./http.js";
import {
  collectKeyedValues,
  findingId,
  sanitizeSnippet,
  serializeComparable,
  similarityRatio,
  tryParseJson,
  uniqueBy
} from "./utils.js";

const SUCCESS_MIN = 200;
const SUCCESS_MAX = 299;
const BLOCKED_STATUSES = new Set([401, 403]);
const NOT_FOUND_STATUSES = new Set([404]);
const DANGEROUS_OBJECT_KEYS = new Set(["__proto__", "prototype", "constructor"]);

export interface BuiltScenario {
  attackerOwn: ConcreteRequest;
  attackerMutated: ConcreteRequest;
  victimControl: ConcreteRequest;
  attackerId: string;
  victimId: string;
}

interface MutationVariant {
  name: string;
  request: ConcreteRequest;
}

interface ScoredVariant {
  name: string;
  request: ConcreteRequest;
  response: ProbeResponse;
  evidence: Evidence[];
  confidence: number;
  vulnerable: boolean;
}

function isSuccess(status: number): boolean {
  return status >= SUCCESS_MIN && status <= SUCCESS_MAX;
}

function isNumericId(id: string): boolean {
  return /^\d+$/.test(id);
}

function normalizeKeyName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function cloneBody(value: unknown): unknown {
  if (value === undefined) {
    return undefined;
  }
  return JSON.parse(JSON.stringify(value));
}

function cloneRequest(request: ConcreteRequest): ConcreteRequest {
  return {
    method: request.method,
    url: request.url,
    headers: { ...request.headers },
    body: cloneBody(request.body)
  };
}

function findIdentifierPair(paramName: string, identifiers: Record<string, IdentifierPair>): IdentifierPair {
  const normalizedParam = normalizeKeyName(paramName);

  if (identifiers[normalizedParam]) {
    return identifiers[normalizedParam];
  }

  for (const [key, value] of Object.entries(identifiers)) {
    const normalizedKey = normalizeKeyName(key);
    if (
      normalizedParam.includes(normalizedKey) ||
      normalizedKey.includes(normalizedParam) ||
      normalizedParam.endsWith(normalizedKey.replace(/id$/, ""))
    ) {
      return value;
    }
  }

  const fallback = Object.values(identifiers)[0];
  if (!fallback) {
    throw new Error("No identifiers configured.");
  }

  return fallback;
}

function maybeFindIdentifierPair(paramName: string, identifiers: Record<string, IdentifierPair>): IdentifierPair | undefined {
  const normalizedParam = normalizeKeyName(paramName);
  if (!normalizedParam) {
    return undefined;
  }

  if (identifiers[normalizedParam]) {
    return identifiers[normalizedParam];
  }

  for (const [key, value] of Object.entries(identifiers)) {
    const normalizedKey = normalizeKeyName(key);
    if (
      normalizedParam.includes(normalizedKey) ||
      normalizedKey.includes(normalizedParam) ||
      normalizedParam.endsWith(normalizedKey.replace(/id$/, ""))
    ) {
      return value;
    }
  }

  return undefined;
}

function getLastSegment(dottedKey: string): string {
  const segments = dottedKey.split(".").filter(Boolean);
  const last = segments.at(-1);
  return last ?? dottedKey;
}

function shouldMutateBodyKey(template: RequestTemplate, bodyKey: string, config: ToolConfig): boolean {
  const pivotKey = template.pathParams[0] ?? template.queryParams[0] ?? template.bodyKeys[0] ?? "";
  const normalizedPivot = normalizeKeyName(getLastSegment(pivotKey));
  const normalizedBodyKey = normalizeKeyName(getLastSegment(bodyKey));
  const lowerBodyKey = bodyKey.toLowerCase();

  if (normalizedBodyKey && normalizedBodyKey === normalizedPivot) {
    return true;
  }

  if (
    config.scan.ownerKeywords.some((keyword) => {
      const normalizedKeyword = normalizeKeyName(keyword);
      return normalizedKeyword.length > 0 && normalizeKeyName(lowerBodyKey).includes(normalizedKeyword);
    })
  ) {
    return true;
  }

  if (maybeFindIdentifierPair(normalizedBodyKey, config.identifiers)) {
    return true;
  }

  return template.bodyKeys.length === 1;
}

function setNestedValue(target: Record<string, unknown>, dottedKey: string, value: string): void {
  const segments = dottedKey.split(".").filter(Boolean);
  if (segments.length === 0) {
    return;
  }

  if (segments.some((segment) => DANGEROUS_OBJECT_KEYS.has(segment))) {
    return;
  }

  let cursor: Record<string, unknown> = target;
  for (let i = 0; i < segments.length - 1; i += 1) {
    const segment = segments[i];
    if (!segment) {
      continue;
    }
    const existing = cursor[segment];
    if (!existing || typeof existing !== "object" || Array.isArray(existing)) {
      cursor[segment] = {};
    }
    cursor = cursor[segment] as Record<string, unknown>;
  }

  const lastSegment = segments[segments.length - 1];
  if (!lastSegment) {
    return;
  }
  cursor[lastSegment] = value;
}

function buildTemplateUrl(baseUrl: string, path: string): URL {
  const normalizedBase = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  return new URL(path.replace(/^\//, ""), normalizedBase);
}

function applyPathParams(rawPath: string, pathParams: string[], id: string): string {
  let output = rawPath;
  for (const paramName of pathParams) {
    const escapedName = escapeRegExp(paramName);
    output = output.replace(new RegExp(`\\{${escapedName}\\}`, "g"), encodeURIComponent(id));
  }
  return output;
}

function baseHeaders(defaultHeaders: Record<string, string>, authHeaders: Record<string, string>): Record<string, string> {
  return {
    ...defaultHeaders,
    ...authHeaders
  };
}

function toConcreteRequest(
  template: RequestTemplate,
  config: ToolConfig,
  authHeaders: Record<string, string>,
  idValue: string
): ConcreteRequest {
  const pathWithId = applyPathParams(template.path, template.pathParams, idValue);
  const url = buildTemplateUrl(config.baseUrl, pathWithId);

  for (const queryParam of template.queryParams) {
    if (!url.searchParams.has(queryParam)) {
      url.searchParams.set(queryParam, idValue);
    }
  }

  const body: Record<string, unknown> = {};
  for (const bodyKey of template.bodyKeys) {
    if (!shouldMutateBodyKey(template, bodyKey, config)) {
      continue;
    }
    setNestedValue(body, bodyKey, idValue);
  }

  const hasBody = template.method !== "GET" && Object.keys(body).length > 0;
  const headers = baseHeaders(config.defaultHeaders, authHeaders);
  if (hasBody) {
    headers["Content-Type"] = "application/json";
  }

  return {
    method: template.method,
    url: url.toString(),
    headers,
    body: hasBody ? body : undefined
  };
}

function mutateUrl(request: ConcreteRequest, transform: (url: URL) => boolean): ConcreteRequest | undefined {
  const candidate = cloneRequest(request);
  const url = new URL(candidate.url);
  const changed = transform(url);
  if (!changed) {
    return undefined;
  }
  candidate.url = url.toString();
  return candidate;
}

function addPathSuffix(request: ConcreteRequest, suffix: string): ConcreteRequest {
  const candidate = cloneRequest(request);
  const url = new URL(candidate.url);
  url.pathname = `${url.pathname.replace(/\/+$/, "")}/${suffix}`;
  candidate.url = url.toString();
  return candidate;
}

function withMethodSwap(request: ConcreteRequest): ConcreteRequest | undefined {
  const methodSwap: Record<string, ConcreteRequest["method"]> = {
    POST: "PUT",
    PUT: "POST",
    PATCH: "PUT"
  };

  const swapped = methodSwap[request.method];
  if (!swapped) {
    return undefined;
  }

  const candidate = cloneRequest(request);
  candidate.method = swapped;
  return candidate;
}

function withHeaderBypass(
  request: ConcreteRequest,
  type: "x-original-url" | "x-forwarded-for",
  attackerOwnRequest: ConcreteRequest
): ConcreteRequest {
  const candidate = cloneRequest(request);
  const ownUrl = new URL(attackerOwnRequest.url);
  if (type === "x-original-url") {
    const ownPathWithQuery = `${ownUrl.pathname}${ownUrl.search}`;
    candidate.headers["X-Original-URL"] = ownPathWithQuery;
    candidate.headers["X-Rewrite-URL"] = ownPathWithQuery;
  } else {
    candidate.headers["X-Forwarded-For"] = "127.0.0.1";
    candidate.headers["X-Forwarded-Host"] = "127.0.0.1";
    candidate.headers["X-Client-IP"] = "127.0.0.1";
  }
  return candidate;
}

function withVersionDowngrade(request: ConcreteRequest): ConcreteRequest | undefined {
  return mutateUrl(request, (url) => {
    const match = url.pathname.match(/\/v(\d+)(?=\/|$)/i);
    if (!match || !match[1]) {
      return false;
    }

    const versionNumber = Number(match[1]);
    if (Number.isNaN(versionNumber) || versionNumber <= 1) {
      return false;
    }

    url.pathname = url.pathname.replace(/\/v\d+(?=\/|$)/i, `/v${versionNumber - 1}`);
    return true;
  });
}

function withTrailingSlash(request: ConcreteRequest): ConcreteRequest | undefined {
  return mutateUrl(request, (url) => {
    if (url.pathname.endsWith("/")) {
      return false;
    }
    url.pathname = `${url.pathname}/`;
    return true;
  });
}

function withDoubleSlashBeforeId(request: ConcreteRequest, victimId: string): ConcreteRequest | undefined {
  return mutateUrl(request, (url) => {
    const encodedVictim = encodeURIComponent(victimId);
    const current = url.pathname;
    const marker = `/${encodedVictim}`;
    if (!current.includes(marker)) {
      return false;
    }
    url.pathname = current.replace(marker, `//${encodedVictim}`);
    return true;
  });
}

export function buildScenarioRequests(template: RequestTemplate, config: ToolConfig): BuiltScenario {
  const pivotKey = template.pathParams[0] ?? template.queryParams[0] ?? template.bodyKeys[0] ?? "id";
  const ids = findIdentifierPair(pivotKey, config.identifiers);

  const attackerOwn = toConcreteRequest(template, config, config.auth.attacker.headers ?? {}, ids.attacker);
  const attackerMutated = toConcreteRequest(template, config, config.auth.attacker.headers ?? {}, ids.victim);
  const victimControl = toConcreteRequest(template, config, config.auth.victim.headers ?? {}, ids.victim);

  return {
    attackerOwn,
    attackerMutated,
    victimControl,
    attackerId: ids.attacker,
    victimId: ids.victim
  };
}

function buildMutationVariants(template: RequestTemplate, scenario: BuiltScenario, config: ToolConfig): MutationVariant[] {
  const variants: MutationVariant[] = [];

  const direct = cloneRequest(scenario.attackerMutated);
  variants.push({ name: "direct-id-swap", request: direct });

  if (template.pathParams.length > 0) {
    const trailing = withTrailingSlash(direct);
    if (trailing) {
      variants.push({ name: "trailing-slash", request: trailing });
    }

    const doubleSlash = withDoubleSlashBeforeId(direct, scenario.victimId);
    if (doubleSlash) {
      variants.push({ name: "double-slash", request: doubleSlash });
    }

    for (const suffix of ["details", "orders", "profile"]) {
      variants.push({
        name: `endpoint-variant-${suffix}`,
        request: addPathSuffix(direct, suffix)
      });
    }
  }

  const versionDowngrade = withVersionDowngrade(direct);
  if (versionDowngrade) {
    variants.push({ name: "version-downgrade", request: versionDowngrade });
  }

  variants.push({
    name: "encoded-space",
    request: toConcreteRequest(template, config, config.auth.attacker.headers ?? {}, `${scenario.victimId} `)
  });

  variants.push({
    name: "multi-id-comma",
    request: toConcreteRequest(
      template,
      config,
      config.auth.attacker.headers ?? {},
      `${scenario.attackerId},${scenario.victimId}`
    )
  });

  variants.push({
    name: "multi-id-dot",
    request: toConcreteRequest(
      template,
      config,
      config.auth.attacker.headers ?? {},
      `${scenario.attackerId}.${scenario.victimId}`
    )
  });

  variants.push({
    name: "null-byte",
    request: toConcreteRequest(template, config, config.auth.attacker.headers ?? {}, `${scenario.victimId}\u0000`)
  });

  if (isNumericId(scenario.victimId)) {
    variants.push({
      name: "leading-zero",
      request: toConcreteRequest(template, config, config.auth.attacker.headers ?? {}, `0${scenario.victimId}`)
    });

    variants.push({
      name: "quoted-numeric",
      request: toConcreteRequest(template, config, config.auth.attacker.headers ?? {}, `"${scenario.victimId}"`)
    });
  }

  const methodSwap = withMethodSwap(direct);
  if (methodSwap) {
    variants.push({ name: "method-swap", request: methodSwap });
  }

  variants.push({
    name: "header-x-original-url",
    request: withHeaderBypass(direct, "x-original-url", scenario.attackerOwn)
  });

  variants.push({
    name: "header-forwarded-for",
    request: withHeaderBypass(direct, "x-forwarded-for", scenario.attackerOwn)
  });

  const deduped = uniqueBy(
    variants,
    (variant) =>
      `${variant.request.method} ${variant.request.url} ${JSON.stringify(variant.request.body ?? null)} ${JSON.stringify(variant.request.headers)}`
  );

  return deduped.slice(0, config.scan.maxMutationVariants);
}

function parseComparable(response: ProbeResponse): string {
  if (response.json !== undefined) {
    return serializeComparable(response.json);
  }

  const parsedJson = tryParseJson(response.text);
  if (parsedJson !== undefined) {
    return serializeComparable(parsedJson);
  }

  return sanitizeSnippet(response.text, 3000);
}

function responseMentions(text: string, expected: string): boolean {
  if (!expected) {
    return false;
  }
  return text.toLowerCase().includes(expected.toLowerCase());
}

function pushEvidence(evidence: Evidence[], reason: string, scoreImpact: number): void {
  evidence.push({ reason, scoreImpact });
}

function classifySeverity(confidence: number, vulnerable: boolean): Finding["severity"] {
  if (!vulnerable) {
    return confidence >= 35 ? "low" : "info";
  }

  if (confidence >= 90) {
    return "critical";
  }
  if (confidence >= 75) {
    return "high";
  }
  if (confidence >= 60) {
    return "medium";
  }
  return "low";
}

function scoreFinding(
  template: RequestTemplate,
  scenario: BuiltScenario,
  responses: { attackerOwn: ProbeResponse; attackerMutated: ProbeResponse; victimControl: ProbeResponse },
  config: ToolConfig,
  variantName: string,
  directMutatedStatus: number
): { confidence: number; vulnerable: boolean; evidence: Evidence[] } {
  const evidence: Evidence[] = [];
  let score = 0;

  pushEvidence(evidence, `Mutation variant used: ${variantName}.`, 0);

  if (responses.attackerOwn.error || responses.attackerMutated.error || responses.victimControl.error) {
    pushEvidence(evidence, "Network or timeout error occurred during one or more probes.", -35);
    score -= 35;
  }

  if (isSuccess(responses.attackerOwn.status)) {
    pushEvidence(evidence, "Attacker can access own resource (baseline valid).", 10);
    score += 10;
  } else {
    pushEvidence(evidence, `Attacker baseline failed (${responses.attackerOwn.status}).`, -20);
    score -= 20;
  }

  if (isSuccess(responses.victimControl.status)) {
    pushEvidence(evidence, "Victim can access victim resource (control valid).", 10);
    score += 10;
  } else {
    pushEvidence(evidence, `Victim control failed (${responses.victimControl.status}).`, -20);
    score -= 20;
  }

  if (BLOCKED_STATUSES.has(responses.attackerMutated.status) || NOT_FOUND_STATUSES.has(responses.attackerMutated.status)) {
    pushEvidence(
      evidence,
      `Mutated attacker request correctly blocked (${responses.attackerMutated.status}).`,
      -45
    );
    score -= 45;
  } else if (isSuccess(responses.attackerMutated.status)) {
    pushEvidence(evidence, "Mutated attacker request returned success status.", 35);
    score += 35;
  }

  const contentType = (responses.attackerMutated.headers["content-type"] ?? "").toLowerCase();
  const location = (responses.attackerMutated.headers["location"] ?? "").toLowerCase();
  const lowerBody = responses.attackerMutated.text.toLowerCase();

  if (contentType.includes("text/html") && /(login|sign in|sign-in|authenticate)/i.test(lowerBody)) {
    pushEvidence(evidence, "Mutated response looks like login HTML rather than protected JSON/API data.", -30);
    score -= 30;
  }

  if (responses.attackerMutated.status >= 300 && responses.attackerMutated.status < 400 && /(login|signin|auth)/i.test(location)) {
    pushEvidence(evidence, "Mutated request redirects to auth flow, likely not a true IDOR data access.", -25);
    score -= 25;
  }

  if (/(forbidden|unauthorized|access denied|permission denied)/i.test(lowerBody)) {
    pushEvidence(evidence, "Mutated response body contains explicit authorization denial text.", -15);
    score -= 15;
  }

  const mutatedComparable = parseComparable(responses.attackerMutated);
  const victimComparable = parseComparable(responses.victimControl);
  const ownComparable = parseComparable(responses.attackerOwn);

  const mutVictSimilarity = similarityRatio(mutatedComparable, victimComparable);
  const mutOwnSimilarity = similarityRatio(mutatedComparable, ownComparable);

  if (isSuccess(responses.attackerMutated.status) && isSuccess(responses.victimControl.status)) {
    if (mutVictSimilarity > 0.85 && mutOwnSimilarity < 0.55) {
      pushEvidence(
        evidence,
        `Mutated response is highly similar to victim control (${mutVictSimilarity.toFixed(2)}) and differs from own (${mutOwnSimilarity.toFixed(2)}).`,
        30
      );
      score += 30;
    } else if (mutVictSimilarity > 0.7 && mutOwnSimilarity < 0.75) {
      pushEvidence(
        evidence,
        `Mutated response resembles victim response (${mutVictSimilarity.toFixed(2)}).`,
        20
      );
      score += 20;
    }
  }

  if (mutOwnSimilarity > 0.95 && isSuccess(responses.attackerMutated.status)) {
    pushEvidence(
      evidence,
      "Mutated and attacker-own responses are nearly identical, possible false-positive due to endpoint not varying by id.",
      -25
    );
    score -= 25;
  }

  const ownerSignals = collectKeyedValues(responses.attackerMutated.json, config.scan.ownerKeywords).join(" ");
  if (ownerSignals && responseMentions(ownerSignals, scenario.victimId)) {
    pushEvidence(evidence, "Owner-related fields in mutated response include victim identifier.", 20);
    score += 20;
  }

  if (
    responses.attackerMutated.text.length < 20 &&
    responses.victimControl.text.length < 20 &&
    responses.attackerMutated.status === responses.victimControl.status
  ) {
    pushEvidence(evidence, "Very small generic responses reduce confidence.", -10);
    score -= 10;
  }

  if (
    responseMentions(responses.attackerMutated.text, scenario.attackerId) &&
    !responseMentions(responses.attackerMutated.text, scenario.victimId)
  ) {
    pushEvidence(evidence, "Mutated response appears tied to attacker id, not victim id.", -10);
    score -= 10;
  }

  if (
    variantName !== "direct-id-swap" &&
    (BLOCKED_STATUSES.has(directMutatedStatus) || NOT_FOUND_STATUSES.has(directMutatedStatus)) &&
    isSuccess(responses.attackerMutated.status)
  ) {
    pushEvidence(
      evidence,
      "Bypass-style mutation succeeded while direct id swap was blocked, matching real-world 403 bypass pattern.",
      15
    );
    score += 15;
  }

  const confidence = Math.max(0, Math.min(100, score));
  const vulnerable =
    confidence >= 60 && isSuccess(responses.attackerMutated.status) && isSuccess(responses.victimControl.status);

  if (!vulnerable && confidence >= 45) {
    pushEvidence(
      evidence,
      "Candidate is suspicious but does not pass strict vulnerability threshold; manual review recommended.",
      0
    );
  }

  if (template.method !== "GET" && config.scan.safeMode) {
    pushEvidence(evidence, "Safe mode is enabled, non-GET methods are conservative-scored.", -5);
  }

  return { confidence, vulnerable, evidence };
}

async function executeMutationVariants(
  variants: MutationVariant[],
  timeoutMs: number
): Promise<Array<{ variant: MutationVariant; response: ProbeResponse }>> {
  const responses = await Promise.all(
    variants.map(async (variant) => ({
      variant,
      response: await executeHttpRequest(variant.request, timeoutMs)
    }))
  );

  return responses;
}

export async function runTemplateProbe(template: RequestTemplate, config: ToolConfig): Promise<Finding> {
  const scenario = buildScenarioRequests(template, config);

  const [attackerOwn, victimControl] = await Promise.all([
    executeHttpRequest(scenario.attackerOwn, config.scan.timeoutMs),
    executeHttpRequest(scenario.victimControl, config.scan.timeoutMs)
  ]);

  const variants = buildMutationVariants(template, scenario, config);
  const variantResponses = await executeMutationVariants(variants, config.scan.timeoutMs);

  const directVariantResponse =
    variantResponses.find((item) => item.variant.name === "direct-id-swap")?.response ?? variantResponses[0]?.response;
  const directStatus = directVariantResponse?.status ?? 0;

  const scoredVariants: ScoredVariant[] = variantResponses.map(({ variant, response }) => {
    const scored = scoreFinding(
      template,
      scenario,
      {
        attackerOwn,
        attackerMutated: response,
        victimControl
      },
      config,
      variant.name,
      directStatus
    );

    return {
      name: variant.name,
      request: variant.request,
      response,
      evidence: scored.evidence,
      confidence: scored.confidence,
      vulnerable: scored.vulnerable
    };
  });

  const sortedVariants = [...scoredVariants].sort((a, b) => b.confidence - a.confidence);
  const best = sortedVariants[0];

  if (!best) {
    throw new Error(`No mutation variants produced for ${template.method} ${template.path}`);
  }

  return {
    id: findingId(`${template.method} ${template.path} ${template.operationId}`),
    operationId: template.operationId,
    method: template.method,
    path: template.path,
    mutationVariant: best.name,
    severity: classifySeverity(best.confidence, best.vulnerable),
    confidence: best.confidence,
    vulnerable: best.vulnerable,
    browserValidated: false,
    evidence: best.evidence,
    variantScores: sortedVariants.map((variant) => ({
      name: variant.name,
      status: variant.response.status,
      confidence: variant.confidence
    })),
    requests: {
      attackerOwn: scenario.attackerOwn,
      attackerMutated: best.request,
      victimControl: scenario.victimControl
    },
    responses: {
      attackerOwn,
      attackerMutated: best.response,
      victimControl
    }
  };
}
