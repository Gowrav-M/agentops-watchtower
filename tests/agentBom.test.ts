import { describe, expect, it } from "vitest";
import { createAgentBom, exportCycloneDxAgentBom, renderAgentBomMarkdown } from "../src/core/agentBom.js";
import type { McpInventory } from "../src/core/mcpInventory.js";
import type { McpToolDescriptor, RiskFinding } from "../src/core/schemas.js";

const inventory: McpInventory = {
  generatedAt: "2026-05-28T00:00:00.000Z",
  sources: [{ path: "mcp.json", client: "cursor", scope: "explicit", format: "json", status: "parsed" }],
  servers: [
    {
      id: "cursor:explicit:safe-docs",
      name: "safe-docs",
      client: "cursor",
      sourcePath: "mcp.json",
      scope: "explicit",
      transport: "http",
      url: "https://developers.openai.com/mcp",
      args: [],
      envKeys: []
    }
  ],
  findings: []
};

const tools: McpToolDescriptor[] = [
  {
    name: "get_workspace_summary",
    description: "Retrieve a private workspace summary and return counts without modifying data.",
    inputSchema: { type: "object", properties: { workspaceId: { type: "string" } } },
    outputSchema: { type: "object", properties: { summary: { type: "string" } } },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false
    }
  }
];

const findings: RiskFinding[] = [
  {
    id: "finding-runtime-secret-to-sink",
    severity: "critical",
    category: "runtime.secret_to_external_sink",
    title: "Secret flowed to external sink",
    description: "Runtime source-to-sink path",
    recommendation: "review",
    target: "read_secret -> external_post"
  }
];

describe("AgentBOM", () => {
  it("creates a machine-readable inventory of MCP servers, tools, and findings", () => {
    const bom = createAgentBom({
      generatedAt: "2026-05-28T00:00:00.000Z",
      inventory,
      tools,
      findings
    });

    expect(bom.summary).toMatchObject({
      configSources: 1,
      mcpServers: 1,
      mcpTools: 1,
      findings: 1,
      critical: 1
    });
    expect(bom.mcpServers[0]).toMatchObject({
      id: "cursor:explicit:safe-docs",
      name: "safe-docs",
      transport: "http",
      url: "https://developers.openai.com/mcp"
    });
    expect(bom.mcpTools[0]).toMatchObject({
      name: "get_workspace_summary",
      readOnly: true,
      destructive: false,
      openWorld: false
    });
    expect(bom.mcpTools[0]?.fingerprint).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("exports a CycloneDX-compatible BOM with MCP components", () => {
    const bom = createAgentBom({
      generatedAt: "2026-05-28T00:00:00.000Z",
      inventory,
      tools,
      findings: []
    });
    const cycloneDx = exportCycloneDxAgentBom(bom);

    expect(cycloneDx.bomFormat).toBe("CycloneDX");
    expect(cycloneDx.specVersion).toBe("1.7");
    expect(cycloneDx.components).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "mcp-server:safe-docs" }),
        expect.objectContaining({ name: "mcp-tool:get_workspace_summary" })
      ])
    );
  });

  it("renders markdown for human review", () => {
    const bom = createAgentBom({
      generatedAt: "2026-05-28T00:00:00.000Z",
      inventory,
      tools,
      findings
    });

    const markdown = renderAgentBomMarkdown(bom);

    expect(markdown).toContain("# Agent Bill of Materials");
    expect(markdown).toContain("safe-docs");
    expect(markdown).toContain("get_workspace_summary");
    expect(markdown).toContain("runtime.secret_to_external_sink");
  });
});
