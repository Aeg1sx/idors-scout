export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface AccountAuth {
  headers?: Record<string, string>;
}

export interface IdentifierPair {
  attacker: string;
  victim: string;
}

export interface ScanOptions {
  safeMode: boolean;
  maxCandidates: number;
  maxMutationVariants: number;
  concurrency: number;
  methods: HttpMethod[];
  includePaths: string[];
  excludePaths: string[];
  idParameterPatterns: string[];
  ownerKeywords: string[];
  timeoutMs: number;
}

export interface PlaywrightOptions {
  enabled: boolean;
  baseUrl?: string;
  attackerStorageState?: string;
  victimStorageState?: string;
  headed: boolean;
  timeoutMs: number;
  screenshotOnValidation: boolean;
  smokePath?: string;
}

export interface ScanTarget {
  method: HttpMethod;
  path: string;
  operationId?: string;
  summary?: string;
  pathParams?: string[];
  queryParams?: string[];
  bodyKeys?: string[];
}

export interface ToolConfig {
  baseUrl: string;
  openApiSpec?: string;
  targets: ScanTarget[];
  auth: {
    attacker: AccountAuth;
    victim: AccountAuth;
  };
  defaultHeaders: Record<string, string>;
  identifiers: Record<string, IdentifierPair>;
  scan: ScanOptions;
  playwright: PlaywrightOptions;
  outputDir: string;
}

export interface RequestTemplate {
  method: HttpMethod;
  path: string;
  operationId: string;
  summary?: string;
  pathParams: string[];
  queryParams: string[];
  bodyKeys: string[];
}

export interface ConcreteRequest {
  method: HttpMethod;
  url: string;
  headers: Record<string, string>;
  body?: unknown;
}

export interface AccountResponses {
  attackerOwn: ProbeResponse;
  attackerMutated: ProbeResponse;
  victimControl: ProbeResponse;
}

export interface ProbeResponse {
  status: number;
  headers: Record<string, string>;
  text: string;
  json?: unknown;
  elapsedMs: number;
  error?: string;
}

export interface Evidence {
  reason: string;
  scoreImpact: number;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  operationId: string;
  method: HttpMethod;
  path: string;
  mutationVariant: string;
  severity: Severity;
  confidence: number;
  vulnerable: boolean;
  browserValidated: boolean;
  evidence: Evidence[];
  variantScores: Array<{
    name: string;
    status: number;
    confidence: number;
  }>;
  requests: {
    attackerOwn: ConcreteRequest;
    attackerMutated: ConcreteRequest;
    victimControl: ConcreteRequest;
  };
  responses: AccountResponses;
}

export interface ScanResult {
  startedAt: string;
  finishedAt: string;
  candidateCount: number;
  executedCount: number;
  findings: Finding[];
  notes: string[];
}
