import type { ConcreteRequest, ProbeResponse } from "./types.js";
import { tryParseJson } from "./utils.js";

function headersToObject(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of headers.entries()) {
    out[key.toLowerCase()] = value;
  }
  return out;
}

export async function executeHttpRequest(request: ConcreteRequest, timeoutMs: number): Promise<ProbeResponse> {
  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(request.url, {
      method: request.method,
      headers: request.headers,
      body: request.body ? JSON.stringify(request.body) : undefined,
      signal: controller.signal
    });

    const text = await response.text();
    return {
      status: response.status,
      headers: headersToObject(response.headers),
      text,
      json: tryParseJson(text),
      elapsedMs: Date.now() - started
    };
  } catch (error) {
    return {
      status: 0,
      headers: {},
      text: "",
      elapsedMs: Date.now() - started,
      error: error instanceof Error ? error.message : String(error)
    };
  } finally {
    clearTimeout(timer);
  }
}
