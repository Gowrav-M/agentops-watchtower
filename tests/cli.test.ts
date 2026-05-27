import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildCli } from "../src/cli.js";

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "watchtower-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("cli", () => {
  it("init creates local watchtower config", async () => {
    const cwd = await makeTempDir();
    const output: string[] = [];
    const cli = buildCli({ cwd, stdout: (line) => output.push(line), stderr: (line) => output.push(line) });

    await cli.parseAsync(["node", "watchtower", "init"], { from: "node" });

    const config = await readFile(join(cwd, ".watchtower", "config.json"), "utf8");
    expect(JSON.parse(config)).toMatchObject({ schemaVersion: 1, storage: "local-jsonl" });
    expect(output.join("\n")).toContain("Initialized");
  });

  it("demo generates markdown and html reports", async () => {
    const cwd = await makeTempDir();
    const output: string[] = [];
    const cli = buildCli({ cwd, stdout: (line) => output.push(line), stderr: (line) => output.push(line) });

    await cli.parseAsync(["node", "watchtower", "demo"], { from: "node" });

    const markdown = await readFile(join(cwd, ".watchtower", "reports", "watchtower-report.md"), "utf8");
    const html = await readFile(join(cwd, ".watchtower", "reports", "watchtower-report.html"), "utf8");
    expect(markdown).toContain("AgentOps Watchtower Report");
    expect(html).toContain("<!doctype html>");
  });
});
