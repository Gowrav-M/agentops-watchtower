import { describe, expect, it } from "vitest";
import { evaluateRuns } from "../src/core/evaluator.js";

describe("evaluator", () => {
  it("fails deterministic checks when a run has failed steps and risky tool calls", () => {
    const results = evaluateRuns([
      {
        id: "run-1",
        agent: "codex",
        startedAt: "2026-05-27T10:00:00.000Z",
        goal: "scan",
        steps: [
          {
            id: "step-1",
            timestamp: "2026-05-27T10:00:01.000Z",
            role: "assistant",
            summary: "failed",
            status: "failed",
            error: "bad"
          }
        ],
        toolCalls: [
          {
            id: "tool-1",
            stepId: "step-1",
            timestamp: "2026-05-27T10:00:01.000Z",
            toolName: "delete_repository",
            arguments: {},
            status: "error"
          }
        ],
        findings: []
      }
    ]);

    expect(results).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "no failed steps", passed: false }),
        expect.objectContaining({ name: "no risky tool names", passed: false })
      ])
    );
  });
});
