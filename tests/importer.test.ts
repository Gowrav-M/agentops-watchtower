import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { importTraceFile } from "../src/core/importer.js";
import { redactSecrets } from "../src/core/redaction.js";

describe("trace importer", () => {
  it("imports Codex-style JSONL sessions into a normalized agent run", async () => {
    const run = await importTraceFile(join(import.meta.dirname, "fixtures", "codex-session.jsonl"));

    expect(run.id).toBe("run-1");
    expect(run.steps).toHaveLength(2);
    expect(run.toolCalls).toHaveLength(1);
    expect(run.toolCalls[0]?.arguments).toEqual({ workspaceId: "demo", apiKey: "[REDACTED]" });
  });

  it("imports richer tool result fields and redacts secrets inside structured results", async () => {
    const run = await importTraceFile(join(import.meta.dirname, "fixtures", "runtime-result.jsonl"));

    expect(run.toolCalls[0]).toMatchObject({
      toolName: "read_secret",
      resultText: "Loaded credential metadata."
    });
    expect(run.toolCalls[0]?.result).toEqual({
      metadata: {
        token: "[REDACTED]",
        label: "ci"
      }
    });
  });

  it("imports markdown transcripts into a normalized run", async () => {
    const run = await importTraceFile(join(import.meta.dirname, "fixtures", "claude-session.md"));

    expect(run.agent).toBe("markdown");
    expect(run.steps.length).toBeGreaterThanOrEqual(2);
    expect(run.toolCalls[0]?.toolName).toBe("delete_repository");
  });

  it("redacts common secret-looking fields recursively", () => {
    const redacted = redactSecrets({
      apiKey: "live-key",
      nested: {
        token: "token",
        keep: "visible"
      }
    });

    expect(redacted).toEqual({
      apiKey: "[REDACTED]",
      nested: {
        token: "[REDACTED]",
        keep: "visible"
      }
    });
  });
});
