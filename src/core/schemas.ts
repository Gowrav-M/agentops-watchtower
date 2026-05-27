import { z } from "zod";

const JsonLiteralSchema = z.union([z.string(), z.number(), z.boolean(), z.null()]);

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export const JsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([JsonLiteralSchema, z.array(JsonValueSchema), z.record(JsonValueSchema)])
);

export const JsonObjectSchema = z.record(JsonValueSchema);

export const IsoDateTimeSchema = z.string().datetime({ offset: true });

export const SeveritySchema = z.enum(["info", "low", "medium", "high", "critical"]);

export const RiskFindingSchema = z
  .object({
    id: z.string().min(1),
    severity: SeveritySchema,
    category: z.string().min(1),
    title: z.string().min(1),
    description: z.string().min(1),
    recommendation: z.string().min(1),
    target: z.string().min(1).optional(),
    evidence: z.array(z.string()).optional()
  })
  .strict();

export const EvalResultSchema = z
  .object({
    id: z.string().min(1),
    name: z.string().min(1),
    passed: z.boolean(),
    message: z.string().optional(),
    severity: SeveritySchema
  })
  .strict();

export const AgentStepSchema = z
  .object({
    id: z.string().min(1),
    timestamp: IsoDateTimeSchema,
    role: z.enum(["system", "user", "assistant", "tool", "unknown"]),
    summary: z.string().min(1),
    status: z.enum(["completed", "failed", "skipped", "running"]),
    error: z.string().optional()
  })
  .strict();

export const ToolCallSchema = z
  .object({
    id: z.string().min(1),
    stepId: z.string().min(1).optional(),
    timestamp: IsoDateTimeSchema,
    toolName: z.string().min(1),
    serverName: z.string().min(1).optional(),
    arguments: JsonObjectSchema.default({}),
    status: z.enum(["success", "error", "blocked", "unknown"]),
    durationMs: z.number().int().nonnegative().optional(),
    resultSummary: z.string().optional(),
    error: z.string().optional()
  })
  .strict();

export const AgentRunSchema = z
  .object({
    id: z.string().min(1),
    agent: z.string().min(1),
    startedAt: IsoDateTimeSchema,
    endedAt: IsoDateTimeSchema.optional(),
    goal: z.string().optional(),
    steps: z.array(AgentStepSchema),
    toolCalls: z.array(ToolCallSchema),
    findings: z.array(RiskFindingSchema).default([])
  })
  .strict();

export const McpToolAnnotationsSchema = z
  .object({
    readOnlyHint: z.boolean().nullable().optional(),
    openWorldHint: z.boolean().nullable().optional(),
    destructiveHint: z.boolean().nullable().optional()
  })
  .passthrough();

export const McpToolDescriptorSchema = z
  .object({
    name: z.string().min(1),
    description: z.string().optional(),
    inputSchema: JsonObjectSchema.optional(),
    outputSchema: JsonValueSchema.nullable().optional(),
    annotations: McpToolAnnotationsSchema.optional()
  })
  .passthrough();

export const McpDescriptorFileSchema = z.union([
  z.array(McpToolDescriptorSchema),
  z
    .object({
      tools: z.array(McpToolDescriptorSchema)
    })
    .passthrough()
]);

export const WatchtowerReportSchema = z
  .object({
    generatedAt: IsoDateTimeSchema,
    summary: z
      .object({
        runs: z.number().int().nonnegative(),
        toolCalls: z.number().int().nonnegative(),
        findings: z.number().int().nonnegative(),
        riskScore: z.number().int().min(0).max(100)
      })
      .strict(),
    runs: z.array(AgentRunSchema),
    findings: z.array(RiskFindingSchema),
    evalResults: z.array(EvalResultSchema)
  })
  .strict();

export type Severity = z.infer<typeof SeveritySchema>;
export type RiskFinding = z.infer<typeof RiskFindingSchema>;
export type EvalResult = z.infer<typeof EvalResultSchema>;
export type AgentStep = z.infer<typeof AgentStepSchema>;
export type ToolCall = z.infer<typeof ToolCallSchema>;
export type AgentRun = z.infer<typeof AgentRunSchema>;
export type McpToolDescriptor = z.infer<typeof McpToolDescriptorSchema>;
export type WatchtowerReport = z.infer<typeof WatchtowerReportSchema>;
