import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { buildCli } from "../src/cli.js";

const PackageJsonSchema = z.object({
  bin: z.record(z.string()),
  scripts: z.record(z.string()),
  version: z.string()
});

describe("package metadata", () => {
  it("builds the dist bin before packing or GitHub installs", async () => {
    const raw = await readFile(join(import.meta.dirname, "..", "package.json"), "utf8");
    const packageJson = PackageJsonSchema.parse(JSON.parse(raw) as unknown);

    expect(packageJson.bin["agentops-watchtower"]).toBe("./dist/cli.js");
    expect(packageJson.scripts["prepack"]).toBe("npm run build");
    expect(packageJson.scripts["prepare"]).toBe("npm run build");
  });

  it("keeps the CLI version aligned with package metadata", async () => {
    const raw = await readFile(join(import.meta.dirname, "..", "package.json"), "utf8");
    const packageJson = PackageJsonSchema.parse(JSON.parse(raw) as unknown);

    expect(buildCli().version()).toBe(packageJson.version);
  });
});
