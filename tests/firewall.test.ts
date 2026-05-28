import { describe, expect, it } from "vitest";
import {
  createFirewallConfigFromTools,
  evaluateFirewallToolCall,
  simulateFirewall,
  type FirewallConfig
} from "../src/core/firewall.js";
import type { AgentRun, McpToolDescriptor } from "../src/core/schemas.js";

const tools: McpToolDescriptor[] = [
  {
    name: "list_projects",
    description: "List projects without changing state.",
    inputSchema: { type: "object", properties: { workspaceId: { type: "string" } } },
    outputSchema: { type: "object", properties: { projects: { type: "array" } } },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false }
  },
  {
    name: "shell_exec",
    description: "Execute a shell command on the local workstation.",
    inputSchema: { type: "object", properties: { command: { type: "string" } } },
    outputSchema: { type: "object", properties: { stdout: { type: "string" } } },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false }
  },
  {
    name: "send_email",
    description: "Send an email to an external recipient.",
    inputSchema: { type: "object", properties: { to: { type: "string" }, body: { type: "string" } } },
    outputSchema: { type: "object", properties: { id: { type: "string" } } },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true }
  }
];

describe("Capability Firewall", () => {
  it("creates least-privilege rules from MCP tool descriptors", () => {
    const config = createFirewallConfigFromTools(tools, { generatedAt: "2026-05-28T00:00:00.000Z" });

    expect(config).toMatchObject({
      schemaVersion: 1,
      defaultDecision: "deny",
      rules: [
        {
          id: "tool-list_projects-allow",
          decision: "allow",
          match: { toolName: "list_projects" }
        },
        {
          id: "tool-shell_exec-deny",
          decision: "deny",
          match: { toolName: "shell_exec" }
        },
        {
          id: "tool-send_email-escalate",
          decision: "escalate",
          match: { toolName: "send_email" }
        }
      ]
    });
  });

  it("denies a tool call when arguments contain forbidden substrings", () => {
    const config: FirewallConfig = {
      schemaVersion: 1,
      generatedAt: "2026-05-28T00:00:00.000Z",
      defaultDecision: "allow",
      rules: [
        {
          id: "block-dangerous-shell",
          decision: "deny",
          severity: "critical",
          reason: "Block destructive shell commands.",
          match: { toolName: "shell_exec" },
          conditions: { forbiddenSubstrings: ["rm -rf", "format c:"] }
        }
      ]
    };

    const decision = evaluateFirewallToolCall(config, {
      timestamp: "2026-05-28T00:00:01.000Z",
      toolName: "shell_exec",
      arguments: { command: "rm -rf /tmp/demo" }
    });

    expect(decision.action).toBe("deny");
    expect(decision.ruleId).toBe("block-dangerous-shell");
    expect(decision.finding).toMatchObject({
      severity: "critical",
      category: "firewall.tool_call_denied",
      target: "shell_exec"
    });
  });

  it("simulates firewall decisions over an agent trace", () => {
    const config = createFirewallConfigFromTools(tools, { generatedAt: "2026-05-28T00:00:00.000Z" });
    const run: AgentRun = {
      id: "run-1",
      agent: "codex",
      startedAt: "2026-05-28T00:00:00.000Z",
      steps: [],
      toolCalls: [
        {
          id: "tool-1",
          timestamp: "2026-05-28T00:00:01.000Z",
          toolName: "list_projects",
          arguments: { workspaceId: "demo" },
          status: "success"
        },
        {
          id: "tool-2",
          timestamp: "2026-05-28T00:00:02.000Z",
          toolName: "shell_exec",
          arguments: { command: "cat package.json" },
          status: "success"
        },
        {
          id: "tool-3",
          timestamp: "2026-05-28T00:00:03.000Z",
          toolName: "send_email",
          arguments: { to: "ops@example.com", body: "done" },
          status: "success"
        }
      ],
      findings: []
    };

    const report = simulateFirewall(config, [run], { generatedAt: "2026-05-28T00:00:04.000Z" });

    expect(report.summary).toMatchObject({ evaluated: 3, allowed: 1, denied: 1, escalated: 1 });
    expect(report.findings.map((finding) => finding.category)).toEqual([
      "firewall.tool_call_denied",
      "firewall.tool_call_requires_approval"
    ]);
  });
});
