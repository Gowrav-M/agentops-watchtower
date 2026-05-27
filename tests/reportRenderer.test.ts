import { describe, expect, it } from "vitest";
import { renderHtmlReport, renderMarkdownReport } from "../src/core/reportRenderer.js";

const report = {
  generatedAt: "2026-05-27T10:00:00.000Z",
  summary: {
    runs: 1,
    toolCalls: 2,
    findings: 1,
    riskScore: 70
  },
  runs: [
    {
      id: "run-1",
      agent: "codex",
      startedAt: "2026-05-27T10:00:00.000Z",
      goal: "scan tools",
      steps: [],
      toolCalls: [],
      findings: []
    }
  ],
  findings: [
    {
      id: "finding-1",
      severity: "high",
      category: "mcp.open_world",
      title: "send_email can change external state",
      description: "The tool sends email outside the local workspace.",
      recommendation: "Require explicit review before use.",
      target: "send_email"
    }
  ],
  evalResults: [
    {
      id: "eval-1",
      name: "no failed steps",
      passed: false,
      message: "One step failed.",
      severity: "medium"
    }
  ]
} as const;

describe("report renderer", () => {
  it("renders Markdown reports with summary, findings, evals, and timeline", () => {
    const markdown = renderMarkdownReport(report);

    expect(markdown).toContain("# AgentOps Watchtower Report");
    expect(markdown).toContain("Risk score: 70");
    expect(markdown).toContain("send_email can change external state");
    expect(markdown).toContain("no failed steps");
  });

  it("escapes HTML report content", () => {
    const html = renderHtmlReport({
      ...report,
      findings: [
        {
          ...report.findings[0],
          title: "<script>alert(1)</script>"
        }
      ]
    });

    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>alert(1)</script>");
  });
});
