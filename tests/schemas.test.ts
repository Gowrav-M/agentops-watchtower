import { describe, expect, it } from "vitest";
import {
  AgentRunSchema,
  McpToolDescriptorSchema,
  WatchtowerReportSchema
} from "../src/core/schemas.js";

describe("schemas", () => {
  it("accepts a strict agent run with tool calls and steps", () => {
    const parsed = AgentRunSchema.parse({
      id: "run-1",
      agent: "codex",
      startedAt: "2026-05-27T10:00:00.000Z",
      goal: "scan tools",
      steps: [
        {
          id: "step-1",
          timestamp: "2026-05-27T10:00:01.000Z",
          role: "assistant",
          summary: "called list_projects",
          status: "completed"
        }
      ],
      toolCalls: [
        {
          id: "tool-1",
          stepId: "step-1",
          timestamp: "2026-05-27T10:00:02.000Z",
          toolName: "list_projects",
          serverName: "workspace",
          arguments: { workspaceId: "demo" },
          status: "success",
          durationMs: 12
        }
      ],
      findings: []
    });

    expect(parsed.toolCalls[0]?.toolName).toBe("list_projects");
  });

  it("rejects unknown report severity values", () => {
    expect(() =>
      WatchtowerReportSchema.parse({
        generatedAt: "2026-05-27T10:00:00.000Z",
        summary: {
          runs: 1,
          toolCalls: 1,
          findings: 1,
          riskScore: 10
        },
        runs: [],
        findings: [
          {
            id: "finding-1",
            severity: "urgent",
            category: "mcp",
            title: "bad",
            description: "bad",
            recommendation: "fix"
          }
        ],
        evalResults: []
      })
    ).toThrow();
  });

  it("allows MCP outputSchema to be present, null, or omitted for accurate warnings", () => {
    const parsed = McpToolDescriptorSchema.parse({
      name: "send_email",
      description: "Send an email.",
      inputSchema: { type: "object", properties: {} },
      outputSchema: null,
      annotations: {
        readOnlyHint: false,
        openWorldHint: true,
        destructiveHint: false
      }
    });

    expect(parsed.outputSchema).toBeNull();
  });
});
