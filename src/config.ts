import { readFile } from "node:fs/promises";
import path from "node:path";
import type { HttpMethod, ToolConfig } from "./types.js";

const ALL_METHODS: HttpMethod[] = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const SAFE_METHODS: HttpMethod[] = ["GET"];

const DEFAULT_CONFIG: Omit<ToolConfig, "baseUrl" | "openApiSpec" | "identifiers" | "auth"> &
  Pick<ToolConfig, "defaultHeaders"> = {
  defaultHeaders: {
    Accept: "application/json"
  },
  scan: {
    safeMode: true,
    maxCandidates: 300,
    maxMutationVariants: 12,
    concurrency: 4,
    methods: [...SAFE_METHODS],
    includePaths: [],
    excludePaths: ["/health", "/metrics", "/status", "/docs"],
    idParameterPatterns: ["id", "_id", "uuid", "guid", "userId", "accountId", "tenantId"],
    ownerKeywords: ["ownerId", "userId", "accountId", "tenantId", "createdBy", "authorId"],
    timeoutMs: 10000
  },
  playwright: {
    enabled: false,
    headed: false,
    timeoutMs: 15000,
    screenshotOnValidation: true
  },
  outputDir: "output"
};

interface RawConfig {
  baseUrl?: string;
  openApiSpec?: string;
  auth?: {
    attacker?: { headers?: Record<string, string> };
    victim?: { headers?: Record<string, string> };
  };
  defaultHeaders?: Record<string, string>;
  identifiers?: Record<string, { attacker?: string; victim?: string }>;
  scan?: Partial<ToolConfig["scan"]>;
  playwright?: Partial<ToolConfig["playwright"]>;
  outputDir?: string;
}

const isHttpMethod = (value: string): value is HttpMethod => ALL_METHODS.includes(value as HttpMethod);
const isUrl = (value: string): boolean => /^https?:\/\//i.test(value);

function resolveMaybeRelative(baseDir: string, value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  if (isUrl(value) || path.isAbsolute(value)) {
    return value;
  }
  return path.resolve(baseDir, value);
}

function normalizeMethods(methods: string[] | undefined, safeMode: boolean): HttpMethod[] {
  if (!methods || methods.length === 0) {
    return safeMode ? [...SAFE_METHODS] : [...ALL_METHODS];
  }

  const normalized = methods.map((method) => method.trim().toUpperCase()).filter(isHttpMethod);
  if (normalized.length === 0) {
    return safeMode ? [...SAFE_METHODS] : [...ALL_METHODS];
  }

  if (!safeMode) {
    return normalized;
  }

  return normalized.filter((method) => SAFE_METHODS.includes(method));
}

function assertRequiredConfig(config: ToolConfig): void {
  if (!config.baseUrl) {
    throw new Error("`baseUrl` is required in config.");
  }

  if (!config.openApiSpec) {
    throw new Error("`openApiSpec` is required in config.");
  }

  if (!config.identifiers || Object.keys(config.identifiers).length === 0) {
    throw new Error("`identifiers` must include at least one attacker/victim id pair.");
  }

  const attackerHeaders = config.auth.attacker.headers;
  const victimHeaders = config.auth.victim.headers;
  if (!attackerHeaders || Object.keys(attackerHeaders).length === 0) {
    throw new Error("`auth.attacker.headers` is required.");
  }
  if (!victimHeaders || Object.keys(victimHeaders).length === 0) {
    throw new Error("`auth.victim.headers` is required.");
  }

  if (config.playwright.enabled) {
    if (!config.playwright.attackerStorageState || !config.playwright.victimStorageState) {
      throw new Error(
        "Playwright validation requires `playwright.attackerStorageState` and `playwright.victimStorageState`."
      );
    }
  }
}

export async function loadConfig(configPath: string): Promise<{ config: ToolConfig; absolutePath: string }> {
  const absolutePath = path.resolve(configPath);
  const configDir = path.dirname(absolutePath);
  const raw = await readFile(absolutePath, "utf8");
  const parsed = JSON.parse(raw) as RawConfig;

  const safeMode = parsed.scan?.safeMode ?? DEFAULT_CONFIG.scan.safeMode;
  const scanMethods = normalizeMethods(parsed.scan?.methods as string[] | undefined, safeMode);

  const config: ToolConfig = {
    baseUrl: parsed.baseUrl ?? "",
    openApiSpec: resolveMaybeRelative(configDir, parsed.openApiSpec) ?? "",
    auth: {
      attacker: {
        headers: parsed.auth?.attacker?.headers ?? {}
      },
      victim: {
        headers: parsed.auth?.victim?.headers ?? {}
      }
    },
    defaultHeaders: {
      ...DEFAULT_CONFIG.defaultHeaders,
      ...(parsed.defaultHeaders ?? {})
    },
    identifiers: Object.fromEntries(
      Object.entries(parsed.identifiers ?? {}).map(([key, value]) => [
        key.toLowerCase(),
        {
          attacker: value.attacker ?? "",
          victim: value.victim ?? ""
        }
      ])
    ),
    scan: {
      ...DEFAULT_CONFIG.scan,
      ...(parsed.scan ?? {}),
      safeMode,
      maxMutationVariants: Math.max(1, parsed.scan?.maxMutationVariants ?? DEFAULT_CONFIG.scan.maxMutationVariants),
      concurrency: Math.max(1, parsed.scan?.concurrency ?? DEFAULT_CONFIG.scan.concurrency),
      methods: scanMethods
    },
    playwright: {
      ...DEFAULT_CONFIG.playwright,
      ...(parsed.playwright ?? {}),
      attackerStorageState: resolveMaybeRelative(configDir, parsed.playwright?.attackerStorageState),
      victimStorageState: resolveMaybeRelative(configDir, parsed.playwright?.victimStorageState)
    },
    outputDir: resolveMaybeRelative(configDir, parsed.outputDir) ?? path.resolve(configDir, DEFAULT_CONFIG.outputDir)
  };

  assertRequiredConfig(config);
  return { config, absolutePath };
}
