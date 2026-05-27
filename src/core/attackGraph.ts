import type { McpInventory } from "./mcpInventory.js";
import { isSensitiveKey } from "./redaction.js";
import { createFinding } from "./risk.js";
import type { AgentRun, JsonValue, McpToolDescriptor, RiskFinding, Severity, ToolCall } from "./schemas.js";

export type AttackGraphNodeKind = "source" | "sink" | "transform" | "approval" | "blocker";
export type AttackGraphEdgeReason =
  | "secret-source-to-external-sink"
  | "untrusted-source-to-privileged-sink"
  | "repo-source-to-external-sink"
  | "blocked-action-to-alternate-sink";

export interface AttackGraphNode {
  id: string;
  runId: string;
  toolCallId: string;
  timestamp: string;
  toolName: string;
  serverName?: string;
  status: ToolCall["status"];
  kind: AttackGraphNodeKind;
  labels: string[];
  evidence: string[];
}

export interface AttackGraphEdge {
  id: string;
  runId: string;
  from: string;
  to: string;
  reason: AttackGraphEdgeReason;
  severity: Severity;
  evidence: string[];
}

export interface AttackGraphReport {
  schemaVersion: 1;
  generatedAt: string;
  summary: {
    runs: number;
    toolCalls: number;
    nodes: number;
    edges: number;
    findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  findings: RiskFinding[];
}

export interface AttackGraphContext {
  tools?: readonly McpToolDescriptor[];
  inventory?: McpInventory;
  generatedAt?: string;
}

const SECRET_SOURCE_PATTERN =
  /(secret|token|credential|password|passwd|api[_-]?key|private[_-]?key|authorization|session[_-]?id|mfa|otp|env|vault|keychain|ssh)/i;
const REPO_SOURCE_PATTERN =
  /(read|list|get|search|grep|cat|open|show|diff|clone|inspect|load)[_\W-]*(repo|repository|file|files|code|git|workspace|project|projects|source)|(git|repo|repository|workspace|source)[_\W-]*(read|search|show|list|diff)/i;
const UNTRUSTED_SOURCE_PATTERN = /(fetch|browser|browse|web|url|http|get[_-]?page|read[_-]?email|email|document|download|crawl|scrape|rss)/i;
const EXTERNAL_SINK_PATTERN =
  /(send|post|publish|tweet|slack|discord|telegram|email|webhook|external|upload|deploy|submit|notify|comment|create[_-]?issue|open[_-]?pr|merge[_-]?pr|push)/i;
const COMMAND_SINK_PATTERN =
  /(shell|exec|execute|run[_-]?command|terminal|powershell|bash|cmd|pwsh|python|node|script|subprocess)/i;
const DESTRUCTIVE_SINK_PATTERN =
  /(delete|destroy|drop|remove|wipe|revoke|overwrite|reset|terminate|purge|format)/i;
const APPROVAL_PATTERN = /(confirm|approve|approval|consent|authorize|permission)/i;
const PROMPT_INJECTION_PATTERN =
  /\b(ignore|forget|override|bypass|disable)\b.{0,80}\b(instructions?|rules?|policy|safety|previous|system)\b|\b(silently|secretly|without\s+user|do\s+not\s+(?:tell|reveal|show))\b|\b(send|upload|exfiltrate|leak|steal)\b.{0,80}\b(secret|token|credential|api\s*key|password|private\s*key)\b/i;

export function analyzeRuns(runs: readonly AgentRun[], context: AttackGraphContext = {}): AttackGraphReport {
  const descriptorByToolName = new Map((context.tools ?? []).map((tool) => [tool.name, tool]));
  const remoteServers = new Set(
    (context.inventory?.servers ?? [])
      .filter((server) => server.transport === "http" || server.transport === "sse")
      .map((server) => server.name)
  );
  const nodes: AttackGraphNode[] = [];
  const edges: AttackGraphEdge[] = [];
  const findings: RiskFinding[] = [];

  for (const run of runs) {
    const priorSources: AttackGraphNode[] = [];
    const priorBlockedActions: AttackGraphNode[] = [];
    const sortedToolCalls = [...run.toolCalls].sort(compareToolCalls);

    for (const toolCall of sortedToolCalls) {
      const descriptor = descriptorByToolName.get(toolCall.toolName);
      const node = classifyToolCall(run.id, toolCall, {
        ...(descriptor === undefined ? {} : { descriptor }),
        remoteServers
      });
      nodes.push(node);

      if (hasLabel(node, "prompt_injection")) {
        findings.push(createPromptInjectionFinding(node));
      }

      if (node.kind === "sink" && isCompletedStatus(node.status)) {
        const sensitiveArgumentFinding = createSensitiveArgumentFinding(node, toolCall);
        if (sensitiveArgumentFinding !== undefined) {
          findings.push(sensitiveArgumentFinding);
        }

        for (const source of priorSources) {
          const edge = createRuntimeEdge(run.id, source, node);
          if (edge !== undefined) {
            edges.push(edge);
            findings.push(createEdgeFinding(source, node, edge));
          }
        }

        for (const blockedAction of priorBlockedActions) {
          if (isPrivilegedSink(node) && isPrivilegedSink(blockedAction)) {
            const edge = createBlockedBypassEdge(run.id, blockedAction, node);
            edges.push(edge);
            findings.push(createEdgeFinding(blockedAction, node, edge));
          }
        }
      }

      if (node.kind === "source" && isCompletedStatus(node.status)) {
        priorSources.push(node);
      }

      if (node.kind === "blocker" && isPrivilegedSink(node)) {
        priorBlockedActions.push(node);
      }
    }
  }

  const sortedFindings = findings.sort((left, right) => left.id.localeCompare(right.id));
  const sortedEdges = edges.sort((left, right) => left.id.localeCompare(right.id));
  const counts = countSeverities(sortedFindings);

  return {
    schemaVersion: 1,
    generatedAt: context.generatedAt ?? new Date().toISOString(),
    summary: {
      runs: runs.length,
      toolCalls: runs.reduce((total, run) => total + run.toolCalls.length, 0),
      nodes: nodes.length,
      edges: sortedEdges.length,
      findings: sortedFindings.length,
      critical: counts.critical,
      high: counts.high,
      medium: counts.medium,
      low: counts.low,
      info: counts.info
    },
    nodes,
    edges: sortedEdges,
    findings: sortedFindings
  };
}

interface ClassificationContext {
  descriptor?: McpToolDescriptor;
  remoteServers: ReadonlySet<string>;
}

function classifyToolCall(runId: string, toolCall: ToolCall, context: ClassificationContext): AttackGraphNode {
  const toolText = `${toolCall.serverName ?? ""} ${toolCall.toolName}`.trim();
  const behaviorText = `${toolText} ${JSON.stringify(toolCall.arguments)}`;
  const labels = new Set<string>();
  const evidence = new Set<string>();

  addPatternLabel(labels, evidence, "secret", SECRET_SOURCE_PATTERN, behaviorText);
  addPatternLabel(labels, evidence, "repo", REPO_SOURCE_PATTERN, behaviorText);
  addPatternLabel(labels, evidence, "untrusted_content", UNTRUSTED_SOURCE_PATTERN, behaviorText);
  addPatternLabel(labels, evidence, "external", EXTERNAL_SINK_PATTERN, toolText);
  addPatternLabel(labels, evidence, "command", COMMAND_SINK_PATTERN, toolText);
  addPatternLabel(labels, evidence, "destructive", DESTRUCTIVE_SINK_PATTERN, toolText);
  addPatternLabel(labels, evidence, "approval", APPROVAL_PATTERN, toolText);

  const sensitiveArguments = collectSensitivePaths(toolCall.arguments);
  if (sensitiveArguments.length > 0) {
    labels.add("secret");
    sensitiveArguments.forEach((path) => evidence.add(`sensitive argument: ${path}`));
  }

  const resultText = collectToolResultText(toolCall);
  const poisonedResults = resultText.filter((text) => PROMPT_INJECTION_PATTERN.test(text));
  if (poisonedResults.length > 0) {
    labels.add("untrusted_content");
    labels.add("prompt_injection");
    poisonedResults.forEach((text) => evidence.add(text.slice(0, 240)));
  }

  const descriptor = context.descriptor;
  if (descriptor?.annotations?.openWorldHint === true) {
    labels.add("external");
  }
  if (descriptor?.annotations?.destructiveHint === true) {
    labels.add("destructive");
  }
  if (descriptor?.annotations?.readOnlyHint === true) {
    labels.add("read_only");
  }

  if (toolCall.serverName !== undefined && context.remoteServers.has(toolCall.serverName)) {
    labels.add("remote_server");
  }

  const kind = classifyKind(toolCall.status, labels);
  return {
    id: `${runId}:${toolCall.id}`,
    runId,
    toolCallId: toolCall.id,
    timestamp: toolCall.timestamp,
    toolName: toolCall.toolName,
    ...(toolCall.serverName === undefined ? {} : { serverName: toolCall.serverName }),
    status: toolCall.status,
    kind,
    labels: [...labels].sort(),
    evidence: [...evidence].sort()
  };
}

function addPatternLabel(labels: Set<string>, evidence: Set<string>, label: string, pattern: RegExp, value: string): void {
  if (pattern.test(value)) {
    labels.add(label);
    evidence.add(value.slice(0, 240));
  }
}

function classifyKind(status: ToolCall["status"], labels: ReadonlySet<string>): AttackGraphNodeKind {
  if (status === "blocked") {
    return "blocker";
  }
  if (labels.has("approval")) {
    return "approval";
  }
  if (labels.has("external") || labels.has("command") || labels.has("destructive")) {
    return "sink";
  }
  if (labels.has("secret") || labels.has("repo") || labels.has("untrusted_content")) {
    return "source";
  }
  return "transform";
}

function createRuntimeEdge(runId: string, source: AttackGraphNode, sink: AttackGraphNode): AttackGraphEdge | undefined {
  if (hasLabel(source, "secret") && hasLabel(sink, "external")) {
    return createEdge(runId, source, sink, "secret-source-to-external-sink", "critical");
  }

  if (hasLabel(source, "untrusted_content") && isPrivilegedSink(sink)) {
    return createEdge(runId, source, sink, "untrusted-source-to-privileged-sink", hasLabel(sink, "command") ? "critical" : "high");
  }

  if (hasLabel(source, "repo") && hasLabel(sink, "external")) {
    return createEdge(runId, source, sink, "repo-source-to-external-sink", "high");
  }

  return undefined;
}

function createBlockedBypassEdge(runId: string, blockedAction: AttackGraphNode, sink: AttackGraphNode): AttackGraphEdge {
  return createEdge(runId, blockedAction, sink, "blocked-action-to-alternate-sink", "high");
}

function createEdge(
  runId: string,
  source: AttackGraphNode,
  sink: AttackGraphNode,
  reason: AttackGraphEdgeReason,
  severity: Severity
): AttackGraphEdge {
  return {
    id: `${runId}:${source.toolCallId}->${sink.toolCallId}:${reason}`,
    runId,
    from: source.id,
    to: sink.id,
    reason,
    severity,
    evidence: [...source.evidence, ...sink.evidence].slice(0, 6)
  };
}

function createEdgeFinding(source: AttackGraphNode, sink: AttackGraphNode, edge: AttackGraphEdge): RiskFinding {
  const categoryByReason: Record<AttackGraphEdgeReason, string> = {
    "secret-source-to-external-sink": "runtime.secret_to_external_sink",
    "untrusted-source-to-privileged-sink": "runtime.untrusted_to_privileged_sink",
    "repo-source-to-external-sink": "runtime.repo_to_external_sink",
    "blocked-action-to-alternate-sink": "runtime.blocked_action_bypass"
  };
  const titleByReason: Record<AttackGraphEdgeReason, string> = {
    "secret-source-to-external-sink": "Secret-like source flowed toward an external sink",
    "untrusted-source-to-privileged-sink": "Untrusted content flowed toward a privileged sink",
    "repo-source-to-external-sink": "Repository context flowed toward an external sink",
    "blocked-action-to-alternate-sink": "Blocked risky action was followed by an alternate sink"
  };
  const recommendationByReason: Record<AttackGraphEdgeReason, string> = {
    "secret-source-to-external-sink": "Keep secrets out of agent context and require explicit approval before any external send.",
    "untrusted-source-to-privileged-sink": "Isolate untrusted content and require human review before command, destructive, or external actions.",
    "repo-source-to-external-sink": "Review whether repository data was intended to leave the local workspace.",
    "blocked-action-to-alternate-sink": "Investigate the run for policy bypass after the first risky action was blocked."
  };

  return createFinding({
    idSeed: edge.id,
    severity: edge.severity,
    category: categoryByReason[edge.reason],
    title: titleByReason[edge.reason],
    description: `${source.toolName} was observed before ${sink.toolName} in the same agent run, creating a risky runtime path.`,
    recommendation: recommendationByReason[edge.reason],
    target: `${source.toolName} -> ${sink.toolName}`,
    evidence: edge.evidence
  });
}

function createPromptInjectionFinding(node: AttackGraphNode): RiskFinding {
  return createFinding({
    idSeed: `${node.id}-prompt-injection`,
    severity: "high",
    category: "runtime.prompt_injection",
    title: `${node.toolName} returned prompt-injection-like content`,
    description: "A tool result or summary contains instruction-like text that could steer the agent away from the user's intent.",
    recommendation: "Treat this content as untrusted input and require review before privileged follow-up tool calls.",
    target: node.toolName,
    evidence: node.evidence.slice(0, 5)
  });
}

function createSensitiveArgumentFinding(node: AttackGraphNode, toolCall: ToolCall): RiskFinding | undefined {
  if (!isPrivilegedSink(node)) {
    return undefined;
  }

  const sensitiveArguments = collectSensitivePaths(toolCall.arguments);
  if (sensitiveArguments.length === 0) {
    return undefined;
  }

  return createFinding({
    idSeed: `${node.id}-sensitive-argument-to-sink`,
    severity: "critical",
    category: "runtime.sensitive_argument_to_sink",
    title: `${node.toolName} received sensitive-looking arguments`,
    description: "A privileged sink tool received arguments whose keys look like credentials or secrets.",
    recommendation: "Remove credentials from tool arguments and pass secrets through reviewed server-side configuration instead.",
    target: node.toolName,
    evidence: sensitiveArguments
  });
}

function compareToolCalls(left: ToolCall, right: ToolCall): number {
  const timestampCompare = left.timestamp.localeCompare(right.timestamp);
  return timestampCompare === 0 ? left.id.localeCompare(right.id) : timestampCompare;
}

function collectSensitivePaths(value: JsonValue, path: readonly string[] = []): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => collectSensitivePaths(item, [...path, String(index)]));
  }

  if (value === null || typeof value !== "object") {
    return [];
  }

  return Object.entries(value).flatMap(([key, child]) => {
    const nextPath = [...path, key];
    const childPaths = collectSensitivePaths(child, nextPath);
    return isSensitiveKey(key) ? [nextPath.join("."), ...childPaths] : childPaths;
  });
}

function collectToolResultText(toolCall: ToolCall): string[] {
  const values: string[] = [];
  if (toolCall.resultSummary !== undefined) {
    values.push(toolCall.resultSummary);
  }
  if (toolCall.resultText !== undefined) {
    values.push(toolCall.resultText);
  }
  if (toolCall.result !== undefined) {
    collectStringValues(toolCall.result, values);
  }
  return values;
}

function collectStringValues(value: JsonValue, values: string[]): void {
  if (typeof value === "string") {
    values.push(value);
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item) => collectStringValues(item, values));
    return;
  }

  if (value !== null && typeof value === "object") {
    Object.values(value).forEach((child) => collectStringValues(child, values));
  }
}

function isCompletedStatus(status: ToolCall["status"]): boolean {
  return status === "success" || status === "unknown";
}

function isPrivilegedSink(node: AttackGraphNode): boolean {
  return hasLabel(node, "external") || hasLabel(node, "command") || hasLabel(node, "destructive");
}

function hasLabel(node: AttackGraphNode, label: string): boolean {
  return node.labels.includes(label);
}

function countSeverities(findings: readonly RiskFinding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  return counts;
}
