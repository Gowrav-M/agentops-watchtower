import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "watchtower-check-reuse-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  vi.doUnmock("../src/core/mcpScanner.js");
  vi.doUnmock("../src/core/mcpInventory.js");
  vi.resetModules();
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("check command context reuse", () => {
  it("reuses descriptor scan and config inventory results for attack graph context", async () => {
    const cwd = await makeTempDir();
    let descriptorScanCalls = 0;
    let inventoryCalls = 0;

    vi.doMock("../src/core/mcpScanner.js", async () => {
      const actual = await vi.importActual<typeof import("../src/core/mcpScanner.js")>("../src/core/mcpScanner.js");
      return {
        ...actual,
        scanMcpDescriptorFile: vi.fn(async (...args: Parameters<typeof actual.scanMcpDescriptorFile>) => {
          descriptorScanCalls += 1;
          return actual.scanMcpDescriptorFile(...args);
        })
      };
    });

    vi.doMock("../src/core/mcpInventory.js", async () => {
      const actual = await vi.importActual<typeof import("../src/core/mcpInventory.js")>("../src/core/mcpInventory.js");
      return {
        ...actual,
        inventoryMcpConfigFiles: vi.fn(async (...args: Parameters<typeof actual.inventoryMcpConfigFiles>) => {
          inventoryCalls += 1;
          return actual.inventoryMcpConfigFiles(...args);
        })
      };
    });

    const { buildCli } = await import("../src/cli.js");
    const cli = buildCli({ cwd, stdout: () => undefined, stderr: () => undefined });

    await cli.parseAsync(
      [
        "node",
        "watchtower",
        "check",
        "--descriptor",
        join(import.meta.dirname, "..", "examples", "mcp", "safe-tools.json"),
        "--config",
        join(import.meta.dirname, "..", "examples", "mcp", "safe-client-config.json"),
        "--trace",
        join(import.meta.dirname, "..", "examples", "traces", "firewall-violation.jsonl"),
        "--fail-on",
        "critical"
      ],
      { from: "node" }
    );

    expect(descriptorScanCalls).toBe(1);
    expect(inventoryCalls).toBe(1);
  });
});
