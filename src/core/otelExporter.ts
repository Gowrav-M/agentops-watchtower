import type { AgentRun, JsonValue } from "./schemas.js";

export interface OTelSpan {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  kind: "INTERNAL" | "CLIENT";
  startTime: string;
  endTime?: string;
  status: {
    code: "UNSET" | "OK" | "ERROR";
    message?: string;
  };
  attributes: Record<string, JsonValue>;
}

export function exportOtelSpans(runs: readonly AgentRun[]): OTelSpan[] {
  return runs.flatMap((run) => {
    const traceId = stableHex(`${run.id}:trace`, 32);
    const agentSpanId = stableHex(`${run.id}:agent`, 16);
    const agentSpan: OTelSpan = {
      traceId,
      spanId: agentSpanId,
      name: `invoke_agent ${run.agent}`,
      kind: "INTERNAL",
      startTime: run.startedAt,
      ...(run.endedAt === undefined ? {} : { endTime: run.endedAt }),
      status: {
        code: run.steps.some((step) => step.status === "failed") ? "ERROR" : "OK"
      },
      attributes: {
        "gen_ai.operation.name": "invoke_agent",
        "gen_ai.agent.name": run.agent,
        "watchtower.run.id": run.id,
        ...(run.goal === undefined ? {} : { "watchtower.run.goal": run.goal })
      }
    };

    const toolSpans: OTelSpan[] = run.toolCalls.map((toolCall) => {
      const statusCode: OTelSpan["status"]["code"] = toolCall.status === "error" ? "ERROR" : "UNSET";

      return {
        traceId,
        spanId: stableHex(`${run.id}:${toolCall.id}`, 16),
        parentSpanId: agentSpanId,
        name: `tools/call ${toolCall.toolName}`,
        kind: "CLIENT",
        startTime: toolCall.timestamp,
        status: {
          code: statusCode,
          ...(toolCall.error === undefined ? {} : { message: toolCall.error })
        },
        attributes: {
          "gen_ai.operation.name": "execute_tool",
          "gen_ai.tool.name": toolCall.toolName,
          "mcp.method.name": "tools/call",
          "watchtower.run.id": run.id,
          "watchtower.tool_call.id": toolCall.id,
          ...(toolCall.serverName === undefined ? {} : { "mcp.server.name": toolCall.serverName }),
          ...(toolCall.durationMs === undefined ? {} : { "watchtower.duration_ms": toolCall.durationMs })
        }
      };
    });

    return [agentSpan, ...toolSpans];
  });
}

function stableHex(input: string, length: number): string {
  let hash = 2166136261;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }

  let hex = (hash >>> 0).toString(16);
  while (hex.length < length) {
    hex += hex;
  }
  return hex.slice(0, length);
}
