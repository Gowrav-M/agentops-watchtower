import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createEvidenceBundle, verifyEvidenceBundle } from "../src/core/evidence.js";

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "watchtower-evidence-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("evidence bundles", () => {
  it("creates a tamper-evident bundle with artifact hashes and admission metadata", async () => {
    const cwd = await makeTempDir();
    const admissionPath = join(cwd, "mcp-admission.json");
    await writeFile(admissionPath, JSON.stringify({ decision: "allow", findings: [] }), "utf8");

    const bundle = await createEvidenceBundle({
      cwd,
      subject: "safe-docs",
      admissionDecision: "allow",
      artifacts: [{ name: "admission", path: admissionPath }]
    });

    expect(bundle.schemaVersion).toBe(1);
    expect(bundle.subject).toBe("safe-docs");
    expect(bundle.admissionDecision).toBe("allow");
    expect(bundle.artifacts[0]?.sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(bundle.integrityHash).toMatch(/^[a-f0-9]{64}$/u);

    const verification = await verifyEvidenceBundle(bundle, cwd);
    expect(verification.ok).toBe(true);
  });

  it("detects modified evidence artifacts", async () => {
    const cwd = await makeTempDir();
    const admissionPath = join(cwd, "mcp-admission.json");
    await writeFile(admissionPath, JSON.stringify({ decision: "allow", findings: [] }), "utf8");
    const bundle = await createEvidenceBundle({
      cwd,
      artifacts: [{ name: "admission", path: admissionPath }]
    });

    await writeFile(admissionPath, JSON.stringify({ decision: "deny", findings: [] }), "utf8");

    const verification = await verifyEvidenceBundle(bundle, cwd);
    expect(verification.ok).toBe(false);
    expect(verification.failures.join("\n")).toContain("hash mismatch");
  });
});
