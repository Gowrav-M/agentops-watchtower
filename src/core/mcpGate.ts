import { createAdmissionReport, type AdmissionReport, type AdmissionCheck } from "./admission.js";
import type { ConfiguredMcpServer, McpInventory } from "./mcpInventory.js";
import type { RiskFinding } from "./schemas.js";

export type McpGateLaunchMode = "dry-run" | "blocked";

export interface McpGateLaunch {
  mode: McpGateLaunchMode;
  reason: string;
  transport: ConfiguredMcpServer["transport"];
  command?: string;
  args?: string[];
  url?: string;
}

export interface McpGateReport {
  schemaVersion: 1;
  generatedAt: string;
  server: ConfiguredMcpServer;
  admission: AdmissionReport;
  launch: McpGateLaunch;
}

export interface CreateMcpGateReportInput {
  generatedAt?: string;
  inventory: McpInventory;
  serverName?: string;
  descriptorFindings?: readonly RiskFinding[];
  baselineFindings?: readonly RiskFinding[];
  allowReview?: boolean;
}

export function selectMcpServer(inventory: McpInventory, serverName: string | undefined): ConfiguredMcpServer {
  if (inventory.servers.length === 0) {
    throw new Error("No MCP servers were found in the provided config files.");
  }

  if (serverName === undefined) {
    if (inventory.servers.length === 1) {
      return inventory.servers[0] as ConfiguredMcpServer;
    }
    throw new Error(`Multiple MCP servers found. Pass --server with one of: ${inventory.servers.map((server) => server.name).join(", ")}`);
  }

  const exactId = inventory.servers.find((server) => server.id === serverName);
  if (exactId !== undefined) {
    return exactId;
  }

  const matches = inventory.servers.filter((server) => server.name === serverName);
  if (matches.length === 1) {
    return matches[0] as ConfiguredMcpServer;
  }
  if (matches.length > 1) {
    throw new Error(`Multiple MCP servers named ${serverName}. Pass a full server id instead.`);
  }

  throw new Error(`MCP server not found: ${serverName}. Available: ${inventory.servers.map((server) => server.name).join(", ")}`);
}

export function createMcpGateReport(input: CreateMcpGateReportInput): McpGateReport {
  const server = selectMcpServer(input.inventory, input.serverName);
  const configFindings = input.inventory.findings.filter((finding) => findingAppliesToServer(finding, server));
  const checks: AdmissionCheck[] = [
    {
      name: "config-inventory",
      status: configFindings.length === 0 ? "passed" : "failed",
      findings: configFindings
    }
  ];

  if (input.descriptorFindings === undefined) {
    checks.push({ name: "descriptor-scan", status: "skipped", findings: [] });
  } else {
    checks.push({
      name: "descriptor-scan",
      status: input.descriptorFindings.length === 0 ? "passed" : "failed",
      findings: [...input.descriptorFindings]
    });
  }

  if (input.baselineFindings === undefined) {
    checks.push({ name: "baseline-diff", status: "skipped", findings: [] });
  } else {
    checks.push({
      name: "baseline-diff",
      status: input.baselineFindings.length === 0 ? "passed" : "failed",
      findings: [...input.baselineFindings]
    });
  }

  const generatedAt = input.generatedAt ?? new Date().toISOString();
  const admission = createAdmissionReport({ generatedAt, checks });

  return {
    schemaVersion: 1,
    generatedAt,
    server,
    admission,
    launch: createLaunchPlan(server, admission, input.allowReview === true)
  };
}

function findingAppliesToServer(finding: RiskFinding, server: ConfiguredMcpServer): boolean {
  return finding.target === server.name || finding.target?.startsWith(`${server.name}.`) === true;
}

function createLaunchPlan(server: ConfiguredMcpServer, admission: AdmissionReport, allowReview: boolean): McpGateLaunch {
  const base = {
    transport: server.transport,
    ...(server.command === undefined ? {} : { command: server.command }),
    ...(server.command === undefined ? {} : { args: server.args }),
    ...(server.url === undefined ? {} : { url: server.url })
  };

  if (admission.decision === "deny") {
    return {
      ...base,
      mode: "blocked",
      reason: "Admission denied. The MCP server must not be launched until critical findings are fixed."
    };
  }

  if (admission.decision === "review" && !allowReview) {
    return {
      ...base,
      mode: "blocked",
      reason: "Admission requires review. Re-run with --allow-review only after human approval."
    };
  }

  return {
    ...base,
    mode: "dry-run",
    reason: "Gate passed. v0.8 records the approved launch plan without starting a protocol proxy."
  };
}
