import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { z } from "zod";
import { createFinding } from "./risk.js";
import { JsonValueSchema, McpToolDescriptorSchema, type JsonValue, type McpToolDescriptor, type RiskFinding } from "./schemas.js";

export const McpToolFingerprintSchema = z
  .object({
    name: z.string().min(1),
    fingerprint: z.string().regex(/^[a-f0-9]{64}$/u),
    descriptionHash: z.string().regex(/^[a-f0-9]{64}$/u),
    inputSchemaHash: z.string().regex(/^[a-f0-9]{64}$/u),
    outputSchemaHash: z.string().regex(/^[a-f0-9]{64}$/u),
    annotationsHash: z.string().regex(/^[a-f0-9]{64}$/u)
  })
  .strict();

export const McpBaselineSchema = z
  .object({
    schemaVersion: z.literal(1),
    generatedAt: z.string().datetime({ offset: true }),
    source: z.string().optional(),
    tools: z.array(McpToolFingerprintSchema)
  })
  .strict();

export type McpToolFingerprint = z.infer<typeof McpToolFingerprintSchema>;
export type McpBaseline = z.infer<typeof McpBaselineSchema>;

export interface McpBaselineOptions {
  generatedAt?: string;
  source?: string;
}

export interface McpBaselineDiff {
  baseline: McpBaseline;
  current: McpBaseline;
  findings: RiskFinding[];
}

export async function readMcpBaselineFile(path: string): Promise<McpBaseline> {
  const raw = JSON.parse(await readFile(path, "utf8")) as unknown;
  return McpBaselineSchema.parse(raw);
}

export function createMcpBaseline(tools: readonly McpToolDescriptor[], options: McpBaselineOptions = {}): McpBaseline {
  const fingerprints = tools
    .map((tool) => createToolFingerprint(McpToolDescriptorSchema.parse(tool)))
    .sort((left, right) => left.name.localeCompare(right.name));

  return {
    schemaVersion: 1,
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    ...(options.source === undefined ? {} : { source: options.source }),
    tools: fingerprints
  };
}

export function compareMcpBaseline(baseline: McpBaseline, currentTools: readonly McpToolDescriptor[]): McpBaselineDiff {
  const current = createMcpBaseline(currentTools, baseline.source === undefined ? {} : { source: baseline.source });
  const approvedByName = new Map(baseline.tools.map((tool) => [tool.name, tool]));
  const currentByName = new Map(current.tools.map((tool) => [tool.name, tool]));
  const findings: RiskFinding[] = [];

  for (const tool of current.tools) {
    const approved = approvedByName.get(tool.name);
    if (approved === undefined) {
      findings.push(createAddedToolFinding(tool));
      continue;
    }
    if (approved.fingerprint !== tool.fingerprint) {
      findings.push(createChangedToolFinding(approved, tool));
    }
  }

  for (const tool of baseline.tools) {
    if (!currentByName.has(tool.name)) {
      findings.push(createRemovedToolFinding(tool));
    }
  }

  return {
    baseline,
    current,
    findings
  };
}

function createToolFingerprint(tool: McpToolDescriptor): McpToolFingerprint {
  const description = tool.description ?? "";
  const inputSchema = JsonValueSchema.parse(tool.inputSchema ?? {});
  const outputSchema = JsonValueSchema.parse(tool.outputSchema ?? null);
  const annotations = JsonValueSchema.parse(tool.annotations ?? {});

  const components: JsonValue = {
    name: tool.name,
    description,
    inputSchema,
    outputSchema,
    annotations
  };

  return {
    name: tool.name,
    fingerprint: hashJson(components),
    descriptionHash: hashJson(description),
    inputSchemaHash: hashJson(inputSchema),
    outputSchemaHash: hashJson(outputSchema),
    annotationsHash: hashJson(annotations)
  };
}

function createAddedToolFinding(tool: McpToolFingerprint): RiskFinding {
  return createFinding({
    idSeed: `${tool.name}-baseline-added`,
    severity: "high",
    category: "mcp.baseline.added",
    title: `${tool.name} was added after MCP baseline approval`,
    description: "The current descriptor contains a tool that was not present in the approved baseline.",
    recommendation: "Review and approve this tool before allowing agents to use the updated MCP server.",
    target: tool.name,
    evidence: [`current fingerprint: ${tool.fingerprint}`]
  });
}

function createChangedToolFinding(approved: McpToolFingerprint, current: McpToolFingerprint): RiskFinding {
  return createFinding({
    idSeed: `${current.name}-baseline-changed`,
    severity: "critical",
    category: "mcp.baseline.changed",
    title: `${current.name} changed after MCP baseline approval`,
    description: "The tool descriptor fingerprint changed, which may indicate tool drift, metadata poisoning, or a server rug pull.",
    recommendation: "Inspect the descriptor diff and re-baseline only after review.",
    target: current.name,
    evidence: [
      `approved fingerprint: ${approved.fingerprint}`,
      `current fingerprint: ${current.fingerprint}`,
      `changed fields: ${changedFields(approved, current).join(", ")}`
    ]
  });
}

function createRemovedToolFinding(tool: McpToolFingerprint): RiskFinding {
  return createFinding({
    idSeed: `${tool.name}-baseline-removed`,
    severity: "medium",
    category: "mcp.baseline.removed",
    title: `${tool.name} was removed after MCP baseline approval`,
    description: "The current descriptor no longer contains a tool that existed in the approved baseline.",
    recommendation: "Confirm that dependent agent workflows no longer require this tool.",
    target: tool.name,
    evidence: [`approved fingerprint: ${tool.fingerprint}`]
  });
}

function changedFields(approved: McpToolFingerprint, current: McpToolFingerprint): string[] {
  const fields: Array<keyof Pick<McpToolFingerprint, "descriptionHash" | "inputSchemaHash" | "outputSchemaHash" | "annotationsHash">> = [
    "descriptionHash",
    "inputSchemaHash",
    "outputSchemaHash",
    "annotationsHash"
  ];
  return fields.filter((field) => approved[field] !== current[field]).map((field) => field.replace(/Hash$/u, ""));
}

function hashJson(value: JsonValue): string {
  return createHash("sha256").update(stableStringify(JsonValueSchema.parse(value))).digest("hex");
}

function stableStringify(value: JsonValue): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }

  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key] ?? null)}`)
      .join(",")}}`;
  }

  return JSON.stringify(value);
}
