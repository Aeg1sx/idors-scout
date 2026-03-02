import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { loadConfig } from "../src/config.js";

test("loadConfig accepts targets-only mode without openApiSpec", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "idor-config-targets-test-"));
  try {
    const configPath = path.join(tempDir, "config.json");
    const rawConfig = {
      baseUrl: "https://api.example.com",
      targets: [
        {
          method: "GET",
          path: "/users/{uid}"
        }
      ],
      auth: {
        attacker: { headers: { Authorization: "Bearer attacker" } },
        victim: { headers: { Authorization: "Bearer victim" } }
      },
      identifiers: {
        uid: { attacker: "100", victim: "200" }
      }
    };

    await writeFile(configPath, JSON.stringify(rawConfig, null, 2), "utf8");

    const { config } = await loadConfig(configPath);
    assert.equal(config.openApiSpec, undefined);
    assert.equal(config.targets.length, 1);

    const firstTarget = config.targets[0];
    assert.ok(firstTarget);
    assert.equal(firstTarget.method, "GET");
    assert.equal(firstTarget.path, "/users/{uid}");
    assert.deepEqual(firstTarget.pathParams, ["uid"]);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("loadConfig rejects config when neither openApiSpec nor targets are provided", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "idor-config-required-test-"));
  try {
    const configPath = path.join(tempDir, "config.json");
    const rawConfig = {
      baseUrl: "https://api.example.com",
      auth: {
        attacker: { headers: { Authorization: "Bearer attacker" } },
        victim: { headers: { Authorization: "Bearer victim" } }
      },
      identifiers: {
        uid: { attacker: "100", victim: "200" }
      }
    };

    await writeFile(configPath, JSON.stringify(rawConfig, null, 2), "utf8");

    await assert.rejects(
      loadConfig(configPath),
      /Either `openApiSpec` or `targets` must be provided in config\./
    );
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});
