import { createMcpBaseline } from "./mcpBaseline.js";
import type { McpInventory, McpInventorySource, ConfiguredMcpServer } from "./mcpInventory.js";
import type { McpToolDescriptor, RiskFinding, Severity } from "./schemas.js";

export interface AgentBomServer {
  id: string;
  name: string;
  client: ConfiguredMcpServer["client"];
  scope: ConfiguredMcpServer["scope"];
  sourcePath: string;
  transport: ConfiguredMcpServer["transport"];
  command?: string;
  args: string[];
  url?: string;
  envKeys: string[];
  findingCount: number;
  highestSeverity?: Severity;
}

export interface AgentBomTool {
  name: string;
  fingerprint: string;
  description?: string;
  readOnly?: boolean | null;
  destructive?: boolean | null;
  openWorld?: boolean | null;
  hasInputSchema: boolean;
  hasOutputSchema: boolean;
}

export interface AgentBomReport {
  schemaVersion: 1;
  generatedAt: string;
  summary: {
    configSources: number;
    mcpServers: number;
    mcpTools: number;
    findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  sources: McpInventorySource[];
  mcpServers: AgentBomServer[];
  mcpTools: AgentBomTool[];
  findings: RiskFinding[];
}

export interface CreateAgentBomInput {
  generatedAt?: string;
  inventory: McpInventory;
  tools?: readonly McpToolDescriptor[];
  findings?: readonly RiskFinding[];
}

export interface CycloneDxBom {
  bomFormat: "CycloneDX";
  specVersion: "1.7";
  version: 1;
  metadata: {
    timestamp: string;
    component: {
      type: "application";
      name: "agentops-watchtower-agent-bom";
    };
  };
  components: CycloneDxComponent[];
}

interface CycloneDxComponent {
  type: "application" | "file";
  "bom-ref": string;
  name: string;
  version?: string;
  properties: Array<{
    name: string;
    value: string;
  }>;
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0
};

export function createAgentBom(input: CreateAgentBomInput): AgentBomReport {
  const tools = input.tools ?? [];
  const allFindings = [...input.inventory.findings, ...(input.findings ?? [])].sort((left, right) => left.id.localeCompare(right.id));
  const counts = countSeverities(allFindings);
  const toolFingerprints = new Map(createMcpBaseline(tools).tools.map((tool) => [tool.name, tool.fingerprint]));

  return {
    schemaVersion: 1,
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    summary: {
      configSources: input.inventory.sources.length,
      mcpServers: input.inventory.servers.length,
      mcpTools: tools.length,
      findings: allFindings.length,
      critical: counts.critical,
      high: counts.high,
      medium: counts.medium,
      low: counts.low,
      info: counts.info
    },
    sources: [...input.inventory.sources].sort((left, right) => left.path.localeCompare(right.path)),
    mcpServers: input.inventory.servers.map((server) => createServerBom(server, allFindings)).sort(compareServers),
    mcpTools: tools.map((tool) => createToolBom(tool, toolFingerprints)).sort((left, right) => left.name.localeCompare(right.name)),
    findings: allFindings
  };
}

export function exportCycloneDxAgentBom(bom: AgentBomReport): CycloneDxBom {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.7",
    version: 1,
    metadata: {
      timestamp: bom.generatedAt,
      component: {
        type: "application",
        name: "agentops-watchtower-agent-bom"
      }
    },
    components: [
      ...bom.sources.map((source): CycloneDxComponent => ({
        type: "file",
        "bom-ref": `mcp-config:${source.path}`,
        name: `mcp-config:${source.path}`,
        properties: [
          { name: "watchtower:kind", value: "mcp-config" },
          { name: "watchtower:client", value: source.client },
          { name: "watchtower:scope", value: source.scope },
          { name: "watchtower:format", value: source.format },
          { name: "watchtower:status", value: source.status }
        ]
      })),
      ...bom.mcpServers.map((server): CycloneDxComponent => ({
        type: "application",
        "bom-ref": `mcp-server:${server.id}`,
        name: `mcp-server:${server.name}`,
        properties: [
          { name: "watchtower:kind", value: "mcp-server" },
          { name: "watchtower:client", value: server.client },
          { name: "watchtower:scope", value: server.scope },
          { name: "watchtower:transport", value: server.transport },
          { name: "watchtower:finding_count", value: String(server.findingCount) },
          ...(server.highestSeverity === undefined ? [] : [{ name: "watchtower:highest_severity", value: server.highestSeverity }])
        ]
      })),
      ...bom.mcpTools.map((tool): CycloneDxComponent => ({
        type: "application",
        "bom-ref": `mcp-tool:${tool.name}`,
        name: `mcp-tool:${tool.name}`,
        version: tool.fingerprint,
        properties: [
          { name: "watchtower:kind", value: "mcp-tool" },
          { name: "watchtower:fingerprint", value: tool.fingerprint },
          { name: "watchtower:read_only", value: String(tool.readOnly ?? "unknown") },
          { name: "watchtower:destructive", value: String(tool.destructive ?? "unknown") },
          { name: "watchtower:open_world", value: String(tool.openWorld ?? "unknown") },
          { name: "watchtower:has_input_schema", value: String(tool.hasInputSchema) },
          { name: "watchtower:has_output_schema", value: String(tool.hasOutputSchema) }
        ]
      }))
    ].sort((left, right) => left["bom-ref"].localeCompare(right["bom-ref"]))
  };
}

export function renderAgentBomMarkdown(bom: AgentBomReport): string {
  const lines: string[] = [
    "# Agent Bill of Materials",
    "",
    `Generated: ${bom.generatedAt}`,
    "",
    "## Summary",
    "",
    `- Config sources: ${bom.summary.configSources}`,
    `- MCP servers: ${bom.summary.mcpServers}`,
    `- MCP tools: ${bom.summary.mcpTools}`,
    `- Findings: ${bom.summary.findings}`,
    `- Critical: ${bom.summary.critical}`,
    `- High: ${bom.summary.high}`,
    "",
    "## MCP Servers",
    "",
    "| Name | Client | Scope | Transport | Findings | Highest Severity |",
    "| --- | --- | --- | --- | ---: | --- |",
    ...bom.mcpServers.map(
      (server) =>
        `| ${server.name} | ${server.client} | ${server.scope} | ${server.transport} | ${server.findingCount} | ${server.highestSeverity ?? "-"} |`
    ),
    "",
    "## MCP Tools",
    "",
    "| Name | Fingerprint | Read-only | Destructive | Open-world |",
    "| --- | --- | --- | --- | --- |",
    ...bom.mcpTools.map(
      (tool) =>
        `| ${tool.name} | ${tool.fingerprint.slice(0, 12)} | ${tool.readOnly ?? "unknown"} | ${tool.destructive ?? "unknown"} | ${tool.openWorld ?? "unknown"} |`
    ),
    "",
    "## Findings",
    ""
  ];

  if (bom.findings.length === 0) {
    lines.push("No findings.");
  } else {
    lines.push("| Severity | Category | Target | Finding |");
    lines.push("| --- | --- | --- | --- |");
    for (const finding of bom.findings) {
      lines.push(`| ${finding.severity} | ${finding.category} | ${finding.target ?? "-"} | ${finding.title} |`);
    }
  }

  return `${lines.join("\n").trimEnd()}\n`;
}

function createServerBom(server: ConfiguredMcpServer, findings: readonly RiskFinding[]): AgentBomServer {
  const serverFindings = findings.filter((finding) => findingAppliesToServer(finding, server.name));
  const highestSeverity = highestFindingSeverity(serverFindings);

  return {
    id: server.id,
    name: server.name,
    client: server.client,
    scope: server.scope,
    sourcePath: server.sourcePath,
    transport: server.transport,
    ...(server.command === undefined ? {} : { command: server.command }),
    args: server.args,
    ...(server.url === undefined ? {} : { url: server.url }),
    envKeys: server.envKeys,
    findingCount: serverFindings.length,
    ...(highestSeverity === undefined ? {} : { highestSeverity })
  };
}

function createToolBom(tool: McpToolDescriptor, fingerprints: ReadonlyMap<string, string>): AgentBomTool {
  return {
    name: tool.name,
    fingerprint: fingerprints.get(tool.name) ?? "0".repeat(64),
    ...(tool.description === undefined ? {} : { description: tool.description }),
    ...(tool.annotations?.readOnlyHint === undefined ? {} : { readOnly: tool.annotations.readOnlyHint }),
    ...(tool.annotations?.destructiveHint === undefined ? {} : { destructive: tool.annotations.destructiveHint }),
    ...(tool.annotations?.openWorldHint === undefined ? {} : { openWorld: tool.annotations.openWorldHint }),
    hasInputSchema: tool.inputSchema !== undefined,
    hasOutputSchema: tool.outputSchema !== undefined && tool.outputSchema !== null
  };
}

function findingAppliesToServer(finding: RiskFinding, serverName: string): boolean {
  return finding.target === serverName || finding.target?.startsWith(`${serverName}.`) === true;
}

function highestFindingSeverity(findings: readonly RiskFinding[]): Severity | undefined {
  return findings
    .map((finding) => finding.severity)
    .sort((left, right) => SEVERITY_RANK[right] - SEVERITY_RANK[left])[0];
}

function countSeverities(findings: readonly RiskFinding[]): Record<Severity, number> {
  const counts = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0])) as Record<Severity, number>;
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  return counts;
}

function compareServers(left: AgentBomServer, right: AgentBomServer): number {
  return left.name.localeCompare(right.name) || left.id.localeCompare(right.id);
}
