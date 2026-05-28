import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { analyzeRuns } from "./attackGraph.js";
import { writeJsonFile } from "./files.js";
import { evaluateFirewallToolCall, type FirewallConfig } from "./firewall.js";
import type { ConfiguredMcpServer } from "./mcpInventory.js";
import type { WatchtowerConfig } from "./policy.js";
import { createFinding } from "./risk.js";
import { redactSecrets } from "./redaction.js";
import { JsonObjectSchema, JsonValueSchema, type AgentRun, type JsonValue, type McpToolDescriptor, type RiskFinding, type ToolCall } from "./schemas.js";

export type JsonRpcId = string | number | null;
export type McpProxyAction = "allow" | "block";
export type McpProxyAuditStatus = "pending" | "success" | "error" | "blocked" | "unknown";

export interface JsonRpcRequest {
  jsonrpc?: string;
  id?: JsonRpcId;
  method?: string;
  params?: unknown;
}

export interface JsonRpcResponse {
  jsonrpc?: string;
  id?: JsonRpcId;
  result?: unknown;
  error?: unknown;
}

export interface JsonRpcErrorResponse {
  jsonrpc: "2.0";
  id: JsonRpcId;
  error: {
    code: -32080;
    message: "Blocked by AgentOps Watchtower policy";
    data: {
      finding: RiskFinding;
    };
  };
}

export interface McpProxyDecision {
  action: McpProxyAction;
  finding?: RiskFinding;
}

export interface McpProxyAuditEvent {
  id: string;
  timestamp: string;
  action: McpProxyAction;
  status: McpProxyAuditStatus;
  toolName: string;
  arguments: Record<string, JsonValue>;
  requestId?: JsonRpcId;
  serverName?: string;
  finding?: RiskFinding;
  resultSummary?: string;
}

export interface McpProxyAuditReport {
  schemaVersion: 1;
  generatedAt: string;
  serverName?: string;
  summary: {
    events: number;
    allowed: number;
    blocked: number;
    completed: number;
    errors: number;
  };
  events: McpProxyAuditEvent[];
}

export interface McpProxyState {
  readonly generatedAt: string;
  readonly serverName?: string;
  readonly tools: readonly McpToolDescriptor[];
  readonly policy: WatchtowerConfig["policy"];
  readonly firewall?: FirewallConfig;
  readonly run: AgentRun;
  readonly events: McpProxyAuditEvent[];
  readonly pendingByRequestId: Map<string, { eventId: string; toolCallId: string }>;
}

export interface CreateMcpProxyStateInput {
  generatedAt?: string;
  serverName?: string;
  tools?: readonly McpToolDescriptor[];
  policy?: Partial<WatchtowerConfig["policy"]>;
  firewall?: FirewallConfig;
}

export interface RunStdioMcpProxyOptions extends CreateMcpProxyStateInput {
  cwd: string;
  server: ConfiguredMcpServer;
  auditPath?: string;
  stdin?: NodeJS.ReadableStream;
  stdout?: NodeJS.WritableStream;
  stderr?: NodeJS.WritableStream;
}

interface ToolCallRequest {
  requestId?: JsonRpcId;
  toolName: string;
  arguments: Record<string, JsonValue>;
}

const DEFAULT_PROXY_POLICY: WatchtowerConfig["policy"] = {
  failOn: "critical",
  requireOutputSchema: true,
  allowDestructiveTools: false,
  allowOpenWorldTools: true,
  detectToolPoisoning: true
};

const COMMAND_TOOL_PATTERN = /(shell|exec|execute|run[_-]?command|terminal|powershell|bash|cmd|pwsh|python|node|script|subprocess)/i;
const DESTRUCTIVE_TOOL_PATTERN = /(delete|destroy|drop|remove|wipe|revoke|overwrite|reset|terminate|purge|format)/i;

export function createMcpProxyState(input: CreateMcpProxyStateInput = {}): McpProxyState {
  const generatedAt = input.generatedAt ?? new Date().toISOString();
  const policy = { ...DEFAULT_PROXY_POLICY, ...(input.policy ?? {}) };
  return {
    generatedAt,
    ...(input.serverName === undefined ? {} : { serverName: input.serverName }),
    tools: input.tools ?? [],
    policy,
    ...(input.firewall === undefined ? {} : { firewall: input.firewall }),
    run: {
      id: `mcp-proxy-${generatedAt.replaceAll(/[:.]/gu, "-")}`,
      agent: "mcp-proxy",
      startedAt: generatedAt,
      ...(input.serverName === undefined ? {} : { goal: `Proxy MCP server ${input.serverName}` }),
      steps: [],
      toolCalls: [],
      findings: []
    },
    events: [],
    pendingByRequestId: new Map()
  };
}

export function evaluateMcpProxyRequest(state: McpProxyState, request: JsonRpcRequest, timestamp = new Date().toISOString()): McpProxyDecision {
  const toolCallRequest = extractToolCallRequest(request);
  if (toolCallRequest === undefined) {
    return { action: "allow" };
  }

  const toolCall = createToolCall(state, toolCallRequest, timestamp, "unknown");
  const firewallFinding = findFirewallFinding(state, toolCall);
  if (firewallFinding !== undefined) {
    const blockedCall = { ...toolCall, status: "blocked" as const, error: firewallFinding.title };
    state.run.toolCalls.push(blockedCall);
    state.run.findings.push(firewallFinding);
    state.events.push(createAuditEvent(state, toolCallRequest, blockedCall, timestamp, "block", "blocked", firewallFinding));
    return { action: "block", finding: firewallFinding };
  }

  const chainFinding = findRuntimeChainFinding(state, toolCall);
  const directFinding = chainFinding ?? findDirectToolFinding(state, toolCall);

  if (directFinding !== undefined) {
    const blockedCall = { ...toolCall, status: "blocked" as const, error: directFinding.title };
    state.run.toolCalls.push(blockedCall);
    state.run.findings.push(directFinding);
    state.events.push(createAuditEvent(state, toolCallRequest, blockedCall, timestamp, "block", "blocked", directFinding));
    return { action: "block", finding: directFinding };
  }

  state.run.toolCalls.push(toolCall);
  const event = createAuditEvent(state, toolCallRequest, toolCall, timestamp, "allow", "pending");
  state.events.push(event);
  if (toolCallRequest.requestId !== undefined && toolCallRequest.requestId !== null) {
    state.pendingByRequestId.set(requestIdKey(toolCallRequest.requestId), { eventId: event.id, toolCallId: toolCall.id });
  }
  return { action: "allow" };
}

export function observeMcpProxyResponse(state: McpProxyState, response: JsonRpcResponse, timestamp = new Date().toISOString()): void {
  if (response.id === undefined || response.id === null) {
    return;
  }
  const pending = state.pendingByRequestId.get(requestIdKey(response.id));
  if (pending === undefined) {
    return;
  }

  const status: Extract<ToolCall["status"], "success" | "error"> = response.error === undefined ? "success" : "error";
  const result = response.result === undefined ? undefined : parseJsonValue(response.result);
  const resultSummary = response.error === undefined ? summarizeUnknown(response.result) : summarizeUnknown(response.error);
  const toolCall = state.run.toolCalls.find((call) => call.id === pending.toolCallId);
  if (toolCall !== undefined) {
    toolCall.status = status;
    if (result !== undefined) {
      toolCall.result = redactSecrets(result);
    }
    if (resultSummary !== undefined) {
      toolCall.resultSummary = resultSummary;
    }
    if (status === "error") {
      toolCall.error = resultSummary ?? "MCP server returned an error.";
    }
  }

  const event = state.events.find((candidate) => candidate.id === pending.eventId);
  if (event !== undefined) {
    event.timestamp = timestamp;
    event.status = status;
    if (resultSummary !== undefined) {
      event.resultSummary = resultSummary;
    }
  }
  state.pendingByRequestId.delete(requestIdKey(response.id));
}

export function createBlockedJsonRpcResponse(request: JsonRpcRequest, decision: McpProxyDecision): JsonRpcErrorResponse {
  if (decision.finding === undefined) {
    throw new Error("Cannot create a blocked JSON-RPC response for an allow decision.");
  }

  return {
    jsonrpc: "2.0",
    id: request.id ?? null,
    error: {
      code: -32080,
      message: "Blocked by AgentOps Watchtower policy",
      data: {
        finding: decision.finding
      }
    }
  };
}

export function createMcpProxyAuditReport(state: McpProxyState, generatedAt = new Date().toISOString()): McpProxyAuditReport {
  const allowed = state.events.filter((event) => event.action === "allow").length;
  const blocked = state.events.filter((event) => event.action === "block").length;
  const completed = state.events.filter((event) => event.status === "success").length;
  const errors = state.events.filter((event) => event.status === "error").length;
  return {
    schemaVersion: 1,
    generatedAt,
    ...(state.serverName === undefined ? {} : { serverName: state.serverName }),
    summary: {
      events: state.events.length,
      allowed,
      blocked,
      completed,
      errors
    },
    events: state.events
  };
}

export async function runStdioMcpProxy(options: RunStdioMcpProxyOptions): Promise<McpProxyAuditReport> {
  if (options.server.transport !== "stdio" || options.server.command === undefined) {
    throw new Error("proxy-mcp currently only supports configured stdio MCP servers.");
  }

  const state = createMcpProxyState({
    serverName: options.server.name,
    ...(options.generatedAt === undefined ? {} : { generatedAt: options.generatedAt }),
    ...(options.tools === undefined ? {} : { tools: options.tools }),
    ...(options.policy === undefined ? {} : { policy: options.policy }),
    ...(options.firewall === undefined ? {} : { firewall: options.firewall })
  });
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const child = spawn(options.server.command, options.server.args, {
    cwd: options.cwd,
    env: process.env,
    shell: false,
    stdio: ["pipe", "pipe", "pipe"]
  });

  const persistAudit = async (): Promise<void> => {
    if (options.auditPath !== undefined) {
      await writeJsonFile(options.auditPath, createMcpProxyAuditReport(state));
    }
  };

  const exitPromise = new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => resolve(code));
  });

  const clientLoop = proxyClientInput({
    input: options.stdin ?? process.stdin,
    childStdin: child.stdin,
    stdout,
    state,
    persistAudit
  });
  const serverLoop = proxyServerOutput({
    input: child.stdout,
    stdout,
    state,
    persistAudit
  });
  const stderrLoop = proxyRawStream(child.stderr, stderr);

  await clientLoop;
  child.stdin.end();
  await Promise.all([serverLoop, stderrLoop]);
  const exitCode = await exitPromise;
  const report = createMcpProxyAuditReport(state);
  await persistAudit();
  if (exitCode !== null && exitCode !== 0) {
    throw new Error(`proxied MCP server exited with code ${exitCode}.`);
  }
  return report;
}

function extractToolCallRequest(request: JsonRpcRequest): ToolCallRequest | undefined {
  if (request.method !== "tools/call" || !isRecord(request.params)) {
    return undefined;
  }

  const name = request.params["name"];
  if (typeof name !== "string" || name.length === 0) {
    return undefined;
  }

  const rawArguments = request.params["arguments"];
  const parsedArguments = JsonObjectSchema.safeParse(rawArguments ?? {});
  return {
    ...(request.id === undefined ? {} : { requestId: request.id }),
    toolName: name,
    arguments: redactSecrets(parsedArguments.success ? parsedArguments.data : {})
  };
}

async function proxyClientInput(input: {
  input: NodeJS.ReadableStream;
  childStdin: NodeJS.WritableStream;
  stdout: NodeJS.WritableStream;
  state: McpProxyState;
  persistAudit: () => Promise<void>;
}): Promise<void> {
  const lines = createInterface({ input: input.input, crlfDelay: Number.POSITIVE_INFINITY });
  for await (const line of lines) {
    const parsed = parseJsonLine(line);
    if (parsed === undefined || !isRecord(parsed)) {
      input.childStdin.write(`${line}\n`);
      continue;
    }

    const request = parsed as JsonRpcRequest;
    const decision = evaluateMcpProxyRequest(input.state, request);
    await input.persistAudit();
    if (decision.action === "block") {
      if (request.id !== undefined) {
        input.stdout.write(`${JSON.stringify(createBlockedJsonRpcResponse(request, decision))}\n`);
      }
      continue;
    }
    input.childStdin.write(`${line}\n`);
  }
}

async function proxyServerOutput(input: {
  input: NodeJS.ReadableStream | null;
  stdout: NodeJS.WritableStream;
  state: McpProxyState;
  persistAudit: () => Promise<void>;
}): Promise<void> {
  if (input.input === null) {
    return;
  }

  const lines = createInterface({ input: input.input, crlfDelay: Number.POSITIVE_INFINITY });
  for await (const line of lines) {
    const parsed = parseJsonLine(line);
    if (parsed !== undefined && isRecord(parsed)) {
      observeMcpProxyResponse(input.state, parsed);
      await input.persistAudit();
    }
    input.stdout.write(`${line}\n`);
  }
}

async function proxyRawStream(input: NodeJS.ReadableStream | null, output: NodeJS.WritableStream): Promise<void> {
  if (input === null) {
    return;
  }

  for await (const chunk of input) {
    output.write(chunk);
  }
}

function parseJsonLine(line: string): unknown {
  try {
    return JSON.parse(line) as unknown;
  } catch {
    return undefined;
  }
}

function createToolCall(
  state: McpProxyState,
  request: ToolCallRequest,
  timestamp: string,
  status: ToolCall["status"]
): ToolCall {
  return {
    id: `proxy-tool-${state.run.toolCalls.length + 1}`,
    timestamp,
    toolName: request.toolName,
    ...(state.serverName === undefined ? {} : { serverName: state.serverName }),
    arguments: request.arguments,
    status
  };
}

function findRuntimeChainFinding(state: McpProxyState, proposedCall: ToolCall): RiskFinding | undefined {
  const graph = analyzeRuns([{ ...state.run, toolCalls: [...state.run.toolCalls, proposedCall] }], {
    tools: state.tools,
    generatedAt: proposedCall.timestamp
  });
  return graph.findings.find((finding) => findingBlocksCurrentCall(finding, proposedCall.toolName));
}

function findFirewallFinding(state: McpProxyState, toolCall: ToolCall): RiskFinding | undefined {
  if (state.firewall === undefined) {
    return undefined;
  }

  const decision = evaluateFirewallToolCall(state.firewall, {
    timestamp: toolCall.timestamp,
    ...(toolCall.serverName === undefined ? {} : { serverName: toolCall.serverName }),
    toolName: toolCall.toolName,
    arguments: toolCall.arguments
  });
  return decision.action === "allow" ? undefined : decision.finding;
}

function findingBlocksCurrentCall(finding: RiskFinding, toolName: string): boolean {
  return (
    finding.category === "runtime.sensitive_argument_to_sink" && finding.target === toolName
  ) || finding.target?.endsWith(` -> ${toolName}`) === true;
}

function findDirectToolFinding(state: McpProxyState, toolCall: ToolCall): RiskFinding | undefined {
  const descriptor = state.tools.find((tool) => tool.name === toolCall.toolName);
  const isDescriptorDestructive = descriptor?.annotations?.destructiveHint === true;
  const isDescriptorOpenWorld = descriptor?.annotations?.openWorldHint === true;
  const isCommand = COMMAND_TOOL_PATTERN.test(toolCall.toolName);
  const isDestructive = DESTRUCTIVE_TOOL_PATTERN.test(toolCall.toolName) || isDescriptorDestructive;

  if ((isDestructive || isCommand) && !state.policy.allowDestructiveTools) {
    return createFinding({
      idSeed: `${state.run.id}-${toolCall.id}-direct-privileged`,
      severity: "high",
      category: isCommand ? "proxy.command_tool_call" : "proxy.destructive_tool_call",
      title: `${toolCall.toolName} was blocked before MCP execution`,
      description: "The MCP proxy blocked a direct command or destructive tool call before forwarding it to the server.",
      recommendation: "Require explicit human approval or narrow the MCP server permissions before allowing this tool call.",
      target: toolCall.toolName,
      evidence: [toolCall.toolName]
    });
  }

  if (isDescriptorOpenWorld && !state.policy.allowOpenWorldTools) {
    return createFinding({
      idSeed: `${state.run.id}-${toolCall.id}-open-world`,
      severity: "medium",
      category: "proxy.open_world_tool_call",
      title: `${toolCall.toolName} was blocked because it can affect external systems`,
      description: "The MCP proxy policy does not allow open-world tool calls without approval.",
      recommendation: "Set a narrower policy, use a read-only tool, or approve this call through a reviewed workflow.",
      target: toolCall.toolName,
      evidence: [toolCall.toolName]
    });
  }

  return undefined;
}

function createAuditEvent(
  state: McpProxyState,
  request: ToolCallRequest,
  toolCall: ToolCall,
  timestamp: string,
  action: McpProxyAction,
  status: McpProxyAuditStatus,
  finding?: RiskFinding
): McpProxyAuditEvent {
  return {
    id: `proxy-event-${state.events.length + 1}`,
    timestamp,
    action,
    status,
    toolName: request.toolName,
    arguments: request.arguments,
    ...(request.requestId === undefined ? {} : { requestId: request.requestId }),
    ...(toolCall.serverName === undefined ? {} : { serverName: toolCall.serverName }),
    ...(finding === undefined ? {} : { finding })
  };
}

function parseJsonValue(value: unknown): JsonValue | undefined {
  const parsed = JsonValueSchema.safeParse(value);
  return parsed.success ? parsed.data : undefined;
}

function summarizeUnknown(value: unknown): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value === "string") {
    return value.slice(0, 500);
  }
  try {
    return JSON.stringify(value).slice(0, 500);
  } catch {
    if (value === null || typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
      return String(value).slice(0, 500);
    }
    return "[unserializable JSON value]";
  }
}

function requestIdKey(id: Exclude<JsonRpcId, null>): string {
  return `${typeof id}:${String(id)}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
