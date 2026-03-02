import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";

export const VOLATILE_KEYWORDS = [
  "timestamp",
  "createdat",
  "updatedat",
  "nonce",
  "signature",
  "requestid",
  "traceid",
  "expires"
];

export function isUrl(value: string): boolean {
  return /^https?:\/\//i.test(value);
}

export async function readTextFromPathOrUrl(value: string, cwd: string): Promise<string> {
  if (isUrl(value)) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      const res = await fetch(value, { signal: controller.signal });
      if (!res.ok) {
        throw new Error(`Failed to fetch spec URL (${res.status}) ${value}`);
      }
      return await res.text();
    } finally {
      clearTimeout(timer);
    }
  }

  const resolved = path.resolve(cwd, value);
  return await readFile(resolved, "utf8");
}

export function tryParseJson<T>(text: string): T | undefined {
  try {
    return JSON.parse(text) as T;
  } catch {
    return undefined;
  }
}

function stableSortObject(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(stableSortObject);
  }
  if (!value || typeof value !== "object") {
    return value;
  }

  const output: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    output[key] = stableSortObject((value as Record<string, unknown>)[key]);
  }
  return output;
}

function shouldDropKey(key: string): boolean {
  const normalized = key.toLowerCase();
  return VOLATILE_KEYWORDS.some((candidate) => normalized.includes(candidate));
}

export function normalizeJsonForComparison(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(normalizeJsonForComparison);
  }

  if (!value || typeof value !== "object") {
    return value;
  }

  const output: Record<string, unknown> = {};
  for (const [key, subValue] of Object.entries(value as Record<string, unknown>)) {
    if (shouldDropKey(key)) {
      continue;
    }
    output[key] = normalizeJsonForComparison(subValue);
  }

  return stableSortObject(output);
}

export function serializeComparable(value: unknown): string {
  return JSON.stringify(normalizeJsonForComparison(value));
}

export function similarityRatio(a: string, b: string): number {
  if (!a && !b) {
    return 1;
  }

  if (!a || !b) {
    return 0;
  }

  const aSet = new Set(a.split(/\W+/).filter(Boolean));
  const bSet = new Set(b.split(/\W+/).filter(Boolean));

  const intersection = [...aSet].filter((token) => bSet.has(token)).length;
  const union = new Set([...aSet, ...bSet]).size;
  return union === 0 ? 0 : intersection / union;
}

export function collectKeyedValues(value: unknown, keyFragments: string[]): string[] {
  const output: string[] = [];
  if (!value || typeof value !== "object") {
    return output;
  }

  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current || typeof current !== "object") {
      continue;
    }

    if (Array.isArray(current)) {
      for (const item of current) {
        stack.push(item);
      }
      continue;
    }

    for (const [key, subValue] of Object.entries(current)) {
      const keyLower = key.toLowerCase();
      if (keyFragments.some((fragment) => keyLower.includes(fragment.toLowerCase()))) {
        output.push(String(subValue));
      }
      stack.push(subValue);
    }
  }

  return output;
}

export function sanitizeSnippet(text: string, maxLength = 300): string {
  const flattened = text.replace(/\s+/g, " ").trim();
  if (flattened.length <= maxLength) {
    return flattened;
  }
  return `${flattened.slice(0, maxLength)}...`;
}

export function findingId(seed: string): string {
  return createHash("sha1").update(seed).digest("hex").slice(0, 12);
}

export function uniqueBy<T>(list: T[], key: (item: T) => string): T[] {
  const map = new Map<string, T>();
  for (const item of list) {
    map.set(key(item), item);
  }
  return [...map.values()];
}
