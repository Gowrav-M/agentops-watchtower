import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

describe("GitHub Action metadata", () => {
  it("publishes a composite action for CI adoption", async () => {
    const action = await readFile(join(import.meta.dirname, "..", "action.yml"), "utf8");

    expect(action).toContain("name: AgentOps Watchtower");
    expect(action).toContain("using: composite");
    expect(action).toContain("descriptor:");
    expect(action).toContain("config:");
    expect(action).toContain("agent-bom");
    expect(action).toContain("admit-mcp");
    expect(action).toContain("attest-mcp");
    expect(action).toContain("proxy-mcp");
    expect(action).toContain("analyze-run");
    expect(action).toContain("report_args=(report");
    expect(action).toContain("watchtower-report.json");
    expect(action).toContain("watchtower.sarif");
  });

  it("includes a reusable workflow example for GitHub users", async () => {
    const workflow = await readFile(join(import.meta.dirname, "..", "examples", "github", "watchtower-action.yml"), "utf8");

    expect(workflow).toContain("uses: Gowrav-M/agentops-watchtower@v1");
    expect(workflow).toContain("descriptor:");
    expect(workflow).toContain("config:");
    expect(workflow).toContain("github/codeql-action/upload-sarif");
  });

  it("documents release history and roadmap", async () => {
    const changelog = await readFile(join(import.meta.dirname, "..", "CHANGELOG.md"), "utf8");
    const roadmap = await readFile(join(import.meta.dirname, "..", "ROADMAP.md"), "utf8");

    expect(changelog).toContain("## 1.2.0");
    expect(changelog).toContain("GitHub Action");
    expect(changelog).toContain("proxy-mcp");
    expect(roadmap).toContain("Streamable HTTP MCP proxy");
    expect(roadmap).toContain("agent transcript adapters");
  });
});
