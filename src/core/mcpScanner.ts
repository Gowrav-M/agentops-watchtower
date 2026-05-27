import { readFile } from "node:fs/promises";
import {
  JsonValueSchema,
  McpDescriptorFileSchema,
  McpToolDescriptorSchema,
  type JsonValue,
  type McpToolDescriptor,
  type RiskFinding
} from "./schemas.js";
import { createFinding } from "./risk.js";
import { isSensitiveKey } from "./redaction.js";

export interface McpScanResult {
  tools: McpToolDescriptor[];
  findings: RiskFinding[];
}

export interface McpScanOptions {
  requireOutputSchema?: boolean;
  allowDestructiveTools?: boolean;
  allowOpenWorldTools?: boolean;
  detectToolPoisoning?: boolean;
}

interface NormalizedMcpScanOptions {
  requireOutputSchema: boolean;
  allowDestructiveTools: boolean;
  allowOpenWorldTools: boolean;
  detectToolPoisoning: boolean;
}

const DESTRUCTIVE_PATTERN = /\b(delete|destroy|drop|remove|wipe|revoke|overwrite|reset|terminate|purge)\b/i;
const MUTATING_PATTERN = /\b(create|update|delete|destroy|drop|remove|send|post|publish|write|edit|merge|deploy|run|execute|trigger|enqueue|submit|revoke|overwrite|reset)\b/i;
const OPEN_WORLD_PATTERN = /\b(email|message|slack|discord|telegram|github|jira|linear|publish|post|tweet|deploy|submit|external|public|internet|webhook)\b/i;
const TOOL_POISONING_PATTERN =
  /\b(ignore|forget|override|bypass|disable)\b.{0,80}\b(instructions?|rules?|policy|safety|previous|system)\b|\b(silently|secretly|without\s+user|do\s+not\s+(?:tell|reveal|show))\b|\b(send|exfiltrate|leak|steal)\b.{0,80}\b(secret|token|credential|api\s*key|password|private\s*key)\b/i;

const DEFAULT_SCAN_OPTIONS: NormalizedMcpScanOptions = {
  requireOutputSchema: true,
  allowDestructiveTools: false,
  allowOpenWorldTools: true,
  detectToolPoisoning: true
};

export async function scanMcpDescriptorFile(path: string, options: McpScanOptions = {}): Promise<McpScanResult> {
  const content = await readFile(path, "utf8");
  let raw: unknown;

  try {
    raw = JSON.parse(content) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown parse error";
    throw new Error(`Could not parse MCP descriptor JSON at ${path}: ${message}`);
  }

  const parsed = McpDescriptorFileSchema.parse(raw);
  const tools = Array.isArray(parsed) ? parsed : parsed.tools;

  return scanMcpTools(tools, options);
}

export function scanMcpTools(tools: readonly McpToolDescriptor[], options: McpScanOptions = {}): McpScanResult {
  const normalizedTools = tools.map((tool) => McpToolDescriptorSchema.parse(tool));
  const scanOptions = normalizeScanOptions(options);
  const findings = normalizedTools.flatMap((tool) => scanTool(tool, scanOptions));

  return {
    tools: normalizedTools,
    findings
  };
}

function scanTool(tool: McpToolDescriptor, options: NormalizedMcpScanOptions): RiskFinding[] {
  const findings: RiskFinding[] = [];
  const description = tool.description ?? "";
  const behaviorText = `${tool.name} ${description}`;
  const annotations = tool.annotations;
  const readOnlyHint = annotations?.readOnlyHint;
  const destructiveHint = annotations?.destructiveHint;
  const openWorldHint = annotations?.openWorldHint;
  const isMutating = MUTATING_PATTERN.test(behaviorText);
  const isDestructive = DESTRUCTIVE_PATTERN.test(behaviorText);
  const isOpenWorld = OPEN_WORLD_PATTERN.test(behaviorText);

  if (readOnlyHint === undefined || readOnlyHint === null) {
    findings.push(
      createFinding({
        idSeed: `${tool.name}-missing-readonly`,
        severity: "high",
        category: "mcp.annotation",
        title: `${tool.name} is missing readOnlyHint`,
        description: "Every submitted MCP tool should explicitly declare whether it only reads data.",
        recommendation: "Set readOnlyHint to true only for tools that never mutate state.",
        target: tool.name
      })
    );
  }

  if (destructiveHint === undefined || destructiveHint === null) {
    findings.push(
      createFinding({
        idSeed: `${tool.name}-missing-destructive`,
        severity: "high",
        category: "mcp.annotation",
        title: `${tool.name} is missing destructiveHint`,
        description: "Every submitted MCP tool should explicitly declare whether it can perform irreversible actions.",
        recommendation: "Set destructiveHint explicitly based on the implementation behavior.",
        target: tool.name
      })
    );
  }

  if (openWorldHint === undefined || openWorldHint === null) {
    findings.push(
      createFinding({
        idSeed: `${tool.name}-missing-open-world`,
        severity: "high",
        category: "mcp.annotation",
        title: `${tool.name} is missing openWorldHint`,
        description: "Every submitted MCP tool should explicitly declare whether it can affect external systems.",
        recommendation: "Set openWorldHint explicitly for tools that send, publish, deploy, or submit externally.",
        target: tool.name
      })
    );
  }

  if (readOnlyHint === true && isMutating) {
    findings.push(
      createFinding({
        idSeed: `${tool.name}-readonly-mismatch`,
        severity: "high",
        category: "mcp.read_only_hint",
        title: `${tool.name} is marked read-only but appears mutating`,
        description: "The tool name or description indicates it may create, update, send, execute, or delete state.",
        recommendation: "Inspect the implementation and set readOnlyHint to false if it can mutate state.",
        target: tool.name,
        evidence: [behaviorText]
      })
    );
  }

  if (isDestructive && (destructiveHint !== true || !options.allowDestructiveTools)) {
    findings.push(
      createFinding({
        idSeed: `${tool.name}-destructive`,
        severity: destructiveHint === true ? "high" : "critical",
        category: "mcp.destructive_hint",
        title: `${tool.name} appears destructive`,
        description: "The tool appears able to delete, revoke, overwrite, reset, or otherwise perform irreversible actions.",
        recommendation:
          destructiveHint === true
            ? "Keep this tool behind clear user confirmation and document the destructive behavior."
            : "Set destructiveHint to true or rename/rework the tool if the implementation is not actually destructive.",
        target: tool.name,
        evidence: [behaviorText]
      })
    );
  }

  if (isOpenWorld && (openWorldHint !== true || !options.allowOpenWorldTools)) {
    findings.push(
      createFinding({
        idSeed: `${tool.name}-open-world`,
        severity: openWorldHint === true ? "medium" : "high",
        category: "mcp.open_world",
        title: `${tool.name} can affect external systems`,
        description: "The tool appears able to send, publish, deploy, or otherwise change state outside the local workspace.",
        recommendation:
          openWorldHint === true
            ? "Document the external side effect and require clear user intent before calling this tool."
            : "Set openWorldHint to true if this tool can change external or public state.",
        target: tool.name,
        evidence: [behaviorText]
      })
    );
  }

  if (description.trim().length < 16) {
    findings.push(
      createFinding({
        idSeed: `${tool.name}-weak-description`,
        severity: "low",
        category: "mcp.description",
        title: `${tool.name} has a weak description`,
        description: "The tool description is too short to explain inputs, side effects, and user-visible results.",
        recommendation: "Use a specific description that states what the tool reads or changes.",
        target: tool.name
      })
    );
  }

  if (options.requireOutputSchema && (!("outputSchema" in tool) || tool.outputSchema === null || tool.outputSchema === undefined)) {
    findings.push(
      createFinding({
        idSeed: `${tool.name}-missing-output-schema`,
        severity: "medium",
        category: "mcp.output_schema",
        title: `${tool.name} is missing outputSchema`,
        description: "The tool does not declare a structured output shape for clients and models.",
        recommendation: "Add an outputSchema so models can use this tool's results more reliably.",
        target: tool.name
      })
    );
  }

  const sensitiveFields = collectSensitiveInputFields(tool.inputSchema);
  for (const field of sensitiveFields) {
    findings.push(
      createFinding({
        idSeed: `${tool.name}-${field}-sensitive-input`,
        severity: "high",
        category: "mcp.sensitive_input",
        title: `${tool.name} asks for sensitive input field ${field}`,
        description: "The input schema includes a field name that appears to request credentials, secrets, or similarly sensitive data.",
        recommendation: "Remove this field from user input, use server-side configuration, or clearly justify why it is required.",
        target: `${tool.name}.${field}`
      })
    );
  }

  const poisoningEvidence = options.detectToolPoisoning ? collectToolPoisoningEvidence(tool) : [];
  if (poisoningEvidence.length > 0) {
    findings.push(
      createFinding({
        idSeed: `${tool.name}-tool-poisoning`,
        severity: "critical",
        category: "mcp.tool_poisoning",
        title: `${tool.name} contains tool-poisoning patterns`,
        description:
          "The tool metadata contains instruction-like text that could manipulate an agent through tool descriptions or schemas.",
        recommendation: "Remove hidden instructions from tool metadata and treat schemas/descriptions as untrusted prompt-injection surfaces.",
        target: tool.name,
        evidence: poisoningEvidence
      })
    );
  }

  return findings;
}

function normalizeScanOptions(options: McpScanOptions): NormalizedMcpScanOptions {
  return {
    requireOutputSchema: options.requireOutputSchema ?? DEFAULT_SCAN_OPTIONS.requireOutputSchema,
    allowDestructiveTools: options.allowDestructiveTools ?? DEFAULT_SCAN_OPTIONS.allowDestructiveTools,
    allowOpenWorldTools: options.allowOpenWorldTools ?? DEFAULT_SCAN_OPTIONS.allowOpenWorldTools,
    detectToolPoisoning: options.detectToolPoisoning ?? DEFAULT_SCAN_OPTIONS.detectToolPoisoning
  };
}

function collectSensitiveInputFields(inputSchema: JsonValue | undefined): string[] {
  if (inputSchema === undefined) {
    return [];
  }

  const parsed = JsonValueSchema.parse(inputSchema);
  const fields = new Set<string>();
  collectSensitiveKeys(parsed, [], fields);
  return [...fields].sort();
}

function collectSensitiveKeys(value: JsonValue, path: readonly string[], fields: Set<string>): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectSensitiveKeys(item, [...path, String(index)], fields));
    return;
  }

  if (value === null || typeof value !== "object") {
    return;
  }

  for (const [key, child] of Object.entries(value)) {
    const nextPath = [...path, key];
    if (isSensitiveKey(key)) {
      fields.add(nextPath.join("."));
    }
    collectSensitiveKeys(child, nextPath, fields);
  }
}

function collectToolPoisoningEvidence(tool: McpToolDescriptor): string[] {
  const evidence: string[] = [];
  const candidates: string[] = [tool.description ?? ""];
  if (tool.inputSchema !== undefined) {
    collectStringValues(tool.inputSchema, candidates);
  }
  if (tool.outputSchema !== undefined && tool.outputSchema !== null) {
    collectStringValues(tool.outputSchema, candidates);
  }

  for (const candidate of candidates) {
    if (TOOL_POISONING_PATTERN.test(candidate)) {
      evidence.push(candidate.slice(0, 240));
    }
  }

  return [...new Set(evidence)].slice(0, 5);
}

function collectStringValues(value: JsonValue, values: string[]): void {
  if (typeof value === "string") {
    values.push(value);
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((child) => collectStringValues(child, values));
    return;
  }

  if (value !== null && typeof value === "object") {
    Object.values(value).forEach((child) => collectStringValues(child, values));
  }
}
