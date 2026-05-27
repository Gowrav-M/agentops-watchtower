import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { importTraceFile } from "../src/core/importer.js";
import { exportOtelSpans } from "../src/core/otelExporter.js";

describe("OpenTelemetry exporter", () => {
  it("exports agent and tool spans with GenAI and MCP semantic attributes", async () => {
    const run = await importTraceFile(join(import.meta.dirname, "fixtures", "codex-session.jsonl"));
    const spans = exportOtelSpans([run]);

    const agentSpan = spans.find((span) => span.name === "invoke_agent codex");
    const toolSpan = spans.find((span) => span.name === "tools/call list_projects");

    expect(agentSpan?.attributes["gen_ai.operation.name"]).toBe("invoke_agent");
    expect(agentSpan?.attributes["gen_ai.agent.name"]).toBe("codex");
    expect(agentSpan?.attributes["watchtower.run.id"]).toBe("run-1");
    expect(toolSpan?.attributes["gen_ai.operation.name"]).toBe("execute_tool");
    expect(toolSpan?.attributes["gen_ai.tool.name"]).toBe("list_projects");
    expect(toolSpan?.attributes["mcp.method.name"]).toBe("tools/call");
  });
});
