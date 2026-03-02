import path from "node:path";
import type { HttpMethod, RequestTemplate, ToolConfig } from "./types.js";
import { readTextFromPathOrUrl, tryParseJson, uniqueBy } from "./utils.js";

interface OpenApiParameter {
  name: string;
  in: "path" | "query" | "header" | "cookie";
  required?: boolean;
  schema?: OpenApiSchema;
}

interface OpenApiRequestBody {
  content?: Record<string, { schema?: OpenApiSchema }>;
}

interface OpenApiOperation {
  operationId?: string;
  summary?: string;
  parameters?: OpenApiParameter[];
  requestBody?: OpenApiRequestBody;
}

interface OpenApiPathItem {
  get?: OpenApiOperation;
  post?: OpenApiOperation;
  put?: OpenApiOperation;
  patch?: OpenApiOperation;
  delete?: OpenApiOperation;
  parameters?: OpenApiParameter[];
}

interface OpenApiSchema {
  $ref?: string;
  type?: string;
  properties?: Record<string, OpenApiSchema>;
  items?: OpenApiSchema;
  allOf?: OpenApiSchema[];
  oneOf?: OpenApiSchema[];
  anyOf?: OpenApiSchema[];
}

interface OpenApiDocument {
  paths?: Record<string, OpenApiPathItem>;
  components?: {
    schemas?: Record<string, OpenApiSchema>;
  };
}

const DANGEROUS_OBJECT_KEYS = new Set(["__proto__", "prototype", "constructor"]);
const MAX_SCHEMA_DEPTH = 30;

const METHOD_MAP: Record<string, HttpMethod> = {
  get: "GET",
  post: "POST",
  put: "PUT",
  patch: "PATCH",
  delete: "DELETE"
};

function toOperationId(method: HttpMethod, apiPath: string): string {
  return `${method.toLowerCase()}_${apiPath.replace(/[^a-zA-Z0-9]+/g, "_").replace(/^_+|_+$/g, "")}`;
}

function shouldIncludePath(apiPath: string, config: ToolConfig): boolean {
  if (config.scan.includePaths.length > 0) {
    const explicitlyIncluded = config.scan.includePaths.some((prefix) => apiPath.startsWith(prefix));
    if (!explicitlyIncluded) {
      return false;
    }
  }

  return !config.scan.excludePaths.some((prefix) => apiPath.startsWith(prefix));
}

function isIdLike(name: string, patterns: string[]): boolean {
  const normalized = name.toLowerCase();
  return patterns.some((pattern) => normalized.includes(pattern.toLowerCase()));
}

function resolveSchemaRef(doc: OpenApiDocument, schema: OpenApiSchema | undefined): OpenApiSchema | undefined {
  if (!schema) {
    return undefined;
  }

  if (!schema.$ref) {
    return schema;
  }

  const prefix = "#/components/schemas/";
  if (!schema.$ref.startsWith(prefix)) {
    return schema;
  }

  const key = schema.$ref.slice(prefix.length);
  return doc.components?.schemas?.[key] ?? schema;
}

function collectIdKeysFromSchema(
  doc: OpenApiDocument,
  schema: OpenApiSchema | undefined,
  patterns: string[],
  trail: string[] = [],
  out: Set<string> = new Set(),
  visited: WeakSet<OpenApiSchema> = new WeakSet(),
  depth = 0
): Set<string> {
  if (depth > MAX_SCHEMA_DEPTH) {
    return out;
  }

  const resolved = resolveSchemaRef(doc, schema);
  if (!resolved) {
    return out;
  }

  if (visited.has(resolved)) {
    return out;
  }
  visited.add(resolved);

  const mergeCandidates = [...(resolved.allOf ?? []), ...(resolved.oneOf ?? []), ...(resolved.anyOf ?? [])];
  for (const candidate of mergeCandidates) {
    collectIdKeysFromSchema(doc, candidate, patterns, trail, out, visited, depth + 1);
  }

  if (resolved.type === "array") {
    collectIdKeysFromSchema(doc, resolved.items, patterns, trail, out, visited, depth + 1);
    return out;
  }

  if (resolved.properties) {
    for (const [prop, child] of Object.entries(resolved.properties)) {
      if (DANGEROUS_OBJECT_KEYS.has(prop)) {
        continue;
      }
      const nextTrail = [...trail, prop];
      if (isIdLike(prop, patterns)) {
        out.add(nextTrail.join("."));
      }
      collectIdKeysFromSchema(doc, child, patterns, nextTrail, out, visited, depth + 1);
    }
  }

  visited.delete(resolved);
  return out;
}

function pathParamsFromTemplate(apiPath: string): string[] {
  const output: string[] = [];
  const regex = /\{([^}]+)\}/g;
  let match: RegExpExecArray | null = regex.exec(apiPath);
  while (match) {
    const param = match[1];
    if (param) {
      output.push(param);
    }
    match = regex.exec(apiPath);
  }
  return output;
}

function extractTemplatesFromPath(
  doc: OpenApiDocument,
  apiPath: string,
  item: OpenApiPathItem,
  config: ToolConfig
): RequestTemplate[] {
  const output: RequestTemplate[] = [];
  const sharedParams = item.parameters ?? [];
  const templatedPathParams = pathParamsFromTemplate(apiPath);

  for (const [methodKey, method] of Object.entries(METHOD_MAP)) {
    if (!config.scan.methods.includes(method)) {
      continue;
    }

    const operation = item[methodKey as keyof OpenApiPathItem] as OpenApiOperation | undefined;
    if (!operation) {
      continue;
    }

    const opParams = [...sharedParams, ...(operation.parameters ?? [])];
    const pathParams = new Set<string>();
    const queryParams = new Set<string>();

    for (const param of opParams) {
      if (param.in === "path") {
        if (isIdLike(param.name, config.scan.idParameterPatterns) || templatedPathParams.length === 1) {
          pathParams.add(param.name);
        }
      }

      if (param.in === "query" && isIdLike(param.name, config.scan.idParameterPatterns)) {
        queryParams.add(param.name);
      }
    }

    for (const param of templatedPathParams) {
      if (isIdLike(param, config.scan.idParameterPatterns) || templatedPathParams.length === 1) {
        pathParams.add(param);
      }
    }

    const jsonSchema =
      operation.requestBody?.content?.["application/json"]?.schema ??
      operation.requestBody?.content?.["application/*+json"]?.schema;
    const bodyKeys = [...collectIdKeysFromSchema(doc, jsonSchema, config.scan.idParameterPatterns)];

    if (pathParams.size === 0 && queryParams.size === 0 && bodyKeys.length === 0) {
      continue;
    }

    output.push({
      method,
      path: apiPath,
      operationId: operation.operationId ?? toOperationId(method, apiPath),
      summary: operation.summary,
      pathParams: [...pathParams],
      queryParams: [...queryParams],
      bodyKeys
    });
  }

  return output;
}

export async function loadTemplatesFromOpenApi(config: ToolConfig, cwd: string): Promise<RequestTemplate[]> {
  const specText = await readTextFromPathOrUrl(config.openApiSpec, cwd);
  const parsed = tryParseJson<OpenApiDocument>(specText);
  if (!parsed) {
    throw new Error(
      `OpenAPI parsing failed. This tool currently expects JSON spec. Received: ${path.basename(config.openApiSpec)}`
    );
  }

  const paths = parsed.paths ?? {};
  const templates: RequestTemplate[] = [];

  for (const [apiPath, pathItem] of Object.entries(paths)) {
    if (!shouldIncludePath(apiPath, config)) {
      continue;
    }
    templates.push(...extractTemplatesFromPath(parsed, apiPath, pathItem, config));
  }

  const uniqueTemplates = uniqueBy(templates, (template) => `${template.method} ${template.path} ${template.operationId}`);
  return uniqueTemplates.slice(0, config.scan.maxCandidates);
}
