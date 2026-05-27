import { basename, extname } from "node:path";
import { readFile } from "node:fs/promises";
import {
  AgentRunSchema,
  type AgentRun,
  type AgentStep,
  type JsonValue,
  type ToolCall
} from "./schemas.js";
import { redactSecrets } from "./redaction.js";

interface SessionRecord {
  type: "session";
  id: string;
  agent?: string;
  startedAt?: string;
  goal?: string;
}

interface StepRecord {
  type: "step";
  id: string;
  timestamp?: string;
  role?: "system" | "user" | "assistant" | "tool" | "unknown";
  summary?: string;
  status?: "completed" | "failed" | "skipped" | "running";
  error?: string;
}

interface ToolCallRecord {
  type: "tool_call";
  id: string;
  stepId?: string;
  timestamp?: string;
  toolName: string;
  serverName?: string;
  arguments?: Record<string, JsonValue>;
  status?: "success" | "error" | "blocked" | "unknown";
  durationMs?: number;
  resultSummary?: string;
  error?: string;
}

type TraceRecord = SessionRecord | StepRecord | ToolCallRecord;

const DEFAULT_TIMESTAMP = "1970-01-01T00:00:00.000Z";

export async function importTraceFile(path: string): Promise<AgentRun> {
  const content = await readFile(path, "utf8");
  const extension = extname(path).toLowerCase();

  if (extension === ".jsonl" || extension === ".ndjson") {
    return importJsonlTrace(content, path);
  }

  if (extension === ".md" || extension === ".markdown" || extension === ".txt") {
    return importMarkdownTrace(content, path);
  }

  throw new Error(`Unsupported trace format for ${path}. Use JSONL, NDJSON, Markdown, or text.`);
}

export function importJsonlTrace(content: string, sourceName = "trace.jsonl"): AgentRun {
  const records = content
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line, index) => parseTraceRecord(line, index + 1));

  const session = records.find((record): record is SessionRecord => record.type === "session");
  const runId = session?.id ?? slugFromName(sourceName);
  const steps: AgentStep[] = [];
  const toolCalls: ToolCall[] = [];

  for (const record of records) {
    if (record.type === "step") {
      steps.push({
        id: record.id,
        timestamp: record.timestamp ?? DEFAULT_TIMESTAMP,
        role: record.role ?? "unknown",
        summary: record.summary ?? "Imported step",
        status: record.status ?? "completed",
        ...(record.error === undefined ? {} : { error: record.error })
      });
    }

    if (record.type === "tool_call") {
      toolCalls.push({
        id: record.id,
        ...(record.stepId === undefined ? {} : { stepId: record.stepId }),
        timestamp: record.timestamp ?? DEFAULT_TIMESTAMP,
        toolName: record.toolName,
        ...(record.serverName === undefined ? {} : { serverName: record.serverName }),
        arguments: redactSecrets(record.arguments ?? {}),
        status: record.status ?? "unknown",
        ...(record.durationMs === undefined ? {} : { durationMs: record.durationMs }),
        ...(record.resultSummary === undefined ? {} : { resultSummary: record.resultSummary }),
        ...(record.error === undefined ? {} : { error: record.error })
      });
    }
  }

  return AgentRunSchema.parse({
    id: runId,
    agent: session?.agent ?? "unknown",
    startedAt: session?.startedAt ?? DEFAULT_TIMESTAMP,
    ...(session?.goal === undefined ? {} : { goal: session.goal }),
    steps,
    toolCalls,
    findings: []
  });
}

export function importMarkdownTrace(content: string, sourceName = "transcript.md"): AgentRun {
  const sections = content.split(/^##\s+Step\s*$/gimu).slice(1);
  const goal = content.match(/^Goal:\s*(.+)$/imu)?.[1]?.trim();
  const steps: AgentStep[] = [];
  const toolCalls: ToolCall[] = [];

  sections.forEach((section, index) => {
    const stepId = `step-${index + 1}`;
    const nonEmptyLine = section
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .find((line) => line.length > 0 && !line.includes(":"));
    const statusLine = section.match(/^Status:\s*(.+)$/imu)?.[1]?.trim().toLowerCase();
    const error = section.match(/^Error:\s*(.+)$/imu)?.[1]?.trim();
    const toolName = section.match(/^Tool:\s*(.+)$/imu)?.[1]?.trim();
    const status = statusLine === "failed" ? "failed" : "completed";

    steps.push({
      id: stepId,
      timestamp: `1970-01-01T00:00:${String(index).padStart(2, "0")}.000Z`,
      role: "assistant",
      summary: nonEmptyLine ?? "Imported markdown step",
      status,
      ...(error === undefined ? {} : { error })
    });

    if (toolName !== undefined && toolName.length > 0) {
      toolCalls.push({
        id: `tool-${index + 1}`,
        stepId,
        timestamp: `1970-01-01T00:00:${String(index).padStart(2, "0")}.000Z`,
        toolName,
        arguments: {},
        status: status === "failed" ? "error" : "success",
        ...(error === undefined ? {} : { error })
      });
    }
  });

  return AgentRunSchema.parse({
    id: slugFromName(sourceName),
    agent: "markdown",
    startedAt: DEFAULT_TIMESTAMP,
    ...(goal === undefined ? {} : { goal }),
    steps,
    toolCalls,
    findings: []
  });
}

function parseTraceRecord(line: string, lineNumber: number): TraceRecord {
  let raw: unknown;
  try {
    raw = JSON.parse(line) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown JSON error";
    throw new Error(`Invalid JSONL record at line ${lineNumber}: ${message}`);
  }

  if (!isRecord(raw) || typeof raw["type"] !== "string") {
    throw new Error(`Invalid JSONL record at line ${lineNumber}: missing string type`);
  }

  const recordType = raw["type"];

  if (recordType === "session") {
    const id = raw["id"];
    const agent = raw["agent"];
    const startedAt = raw["startedAt"];
    const goal = raw["goal"];
    if (typeof id !== "string") {
      throw new Error(`Invalid session record at line ${lineNumber}: missing id`);
    }
    return {
      type: "session",
      id,
      ...(typeof agent === "string" ? { agent } : {}),
      ...(typeof startedAt === "string" ? { startedAt } : {}),
      ...(typeof goal === "string" ? { goal } : {})
    };
  }

  if (recordType === "step") {
    const id = raw["id"];
    const timestamp = raw["timestamp"];
    const role = raw["role"];
    const summary = raw["summary"];
    const status = raw["status"];
    const error = raw["error"];
    if (typeof id !== "string") {
      throw new Error(`Invalid step record at line ${lineNumber}: missing id`);
    }
    return {
      type: "step",
      id,
      ...(typeof timestamp === "string" ? { timestamp } : {}),
      ...(isRole(role) ? { role } : {}),
      ...(typeof summary === "string" ? { summary } : {}),
      ...(isStepStatus(status) ? { status } : {}),
      ...(typeof error === "string" ? { error } : {})
    };
  }

  if (recordType === "tool_call") {
    const id = raw["id"];
    const toolName = raw["toolName"];
    const stepId = raw["stepId"];
    const timestamp = raw["timestamp"];
    const serverName = raw["serverName"];
    const args = raw["arguments"];
    const status = raw["status"];
    const durationMs = raw["durationMs"];
    const resultSummary = raw["resultSummary"];
    const error = raw["error"];
    if (typeof id !== "string" || typeof toolName !== "string") {
      throw new Error(`Invalid tool_call record at line ${lineNumber}: missing id or toolName`);
    }
    return {
      type: "tool_call",
      id,
      toolName,
      ...(typeof stepId === "string" ? { stepId } : {}),
      ...(typeof timestamp === "string" ? { timestamp } : {}),
      ...(typeof serverName === "string" ? { serverName } : {}),
      ...(isJsonObject(args) ? { arguments: args } : {}),
      ...(isToolStatus(status) ? { status } : {}),
      ...(typeof durationMs === "number" && Number.isInteger(durationMs) && durationMs >= 0
        ? { durationMs }
        : {}),
      ...(typeof resultSummary === "string" ? { resultSummary } : {}),
      ...(typeof error === "string" ? { error } : {})
    };
  }

  throw new Error(`Unsupported trace record type at line ${lineNumber}: ${recordType}`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isJsonObject(value: unknown): value is Record<string, JsonValue> {
  return isRecord(value);
}

function isRole(value: unknown): value is AgentStep["role"] {
  return value === "system" || value === "user" || value === "assistant" || value === "tool" || value === "unknown";
}

function isStepStatus(value: unknown): value is AgentStep["status"] {
  return value === "completed" || value === "failed" || value === "skipped" || value === "running";
}

function isToolStatus(value: unknown): value is ToolCall["status"] {
  return value === "success" || value === "error" || value === "blocked" || value === "unknown";
}

function slugFromName(name: string): string {
  const base = basename(name).replace(/\.[^.]+$/u, "");
  return (
    base
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "imported-run"
  );
}
