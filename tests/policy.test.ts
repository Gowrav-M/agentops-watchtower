import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildCli } from "../src/cli.js";
import { loadWatchtowerConfig, shouldFailForFindings } from "../src/core/policy.js";
import type { RiskFinding } from "../src/core/schemas.js";

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "watchtower-policy-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("policy", () => {
  it("loads v0.2 policy defaults when no config exists", async () => {
    const config = await loadWatchtowerConfig(await makeTempDir());

    expect(config.policy.failOn).toBe("critical");
    expect(config.policy.detectToolPoisoning).toBe(true);
  });

  it("loads fail thresholds from watchtower.config.json", async () => {
    const cwd = await makeTempDir();
    await writeFile(
      join(cwd, "watchtower.config.json"),
      JSON.stringify({ schemaVersion: 1, storage: "local-jsonl", policy: { failOn: "high" } }),
      "utf8"
    );

    const config = await loadWatchtowerConfig(cwd);

    expect(config.policy.failOn).toBe("high");
  });

  it("decides whether findings violate the configured threshold", () => {
    const finding: RiskFinding = {
      id: "finding-1",
      severity: "high",
      category: "mcp.test",
      title: "high risk",
      description: "high risk",
      recommendation: "fix"
    };

    expect(shouldFailForFindings([finding], "critical")).toBe(false);
    expect(shouldFailForFindings([finding], "high")).toBe(true);
  });

  it("scan-mcp exits non-zero when findings meet --fail-on threshold", async () => {
    const cwd = await makeTempDir();
    const cli = buildCli({ cwd, stdout: () => undefined, stderr: () => undefined });

    await expect(
      cli.parseAsync(["node", "watchtower", "scan-mcp", join(import.meta.dirname, "fixtures", "poisoned-tools.json"), "--fail-on", "high"], {
        from: "node"
      })
    ).rejects.toThrow(/Policy threshold failed/u);

    const scan = await readFile(join(cwd, ".watchtower", "reports", "mcp-scan.json"), "utf8");
    expect(scan).toContain("mcp.tool_poisoning");
  });
});
