import { describe, expect, it } from "vitest";
import { createAdmissionReport } from "../src/core/admission.js";
import type { RiskFinding } from "../src/core/schemas.js";

function finding(severity: RiskFinding["severity"], category: string): RiskFinding {
  return {
    id: `finding-${severity}-${category}`,
    severity,
    category,
    title: `${severity} finding`,
    description: `${severity} finding`,
    recommendation: "review"
  };
}

describe("MCP admission", () => {
  it("allows MCP admission when all checks have no findings", () => {
    const report = createAdmissionReport({
      generatedAt: "2026-05-27T00:00:00.000Z",
      checks: [
        { name: "config-inventory", status: "passed", findings: [] },
        { name: "descriptor-scan", status: "passed", findings: [] }
      ]
    });

    expect(report.decision).toBe("allow");
    expect(report.summary.findings).toBe(0);
    expect(report.nextActions).toContain("Allow MCP server only within the reviewed scope.");
  });

  it("requires review for medium or high findings", () => {
    const report = createAdmissionReport({
      generatedAt: "2026-05-27T00:00:00.000Z",
      checks: [{ name: "descriptor-scan", status: "failed", findings: [finding("high", "mcp.open_world")] }]
    });

    expect(report.decision).toBe("review");
    expect(report.summary.high).toBe(1);
    expect(report.nextActions).toContain("Require human security review before enabling this MCP server.");
  });

  it("denies admission for critical findings", () => {
    const report = createAdmissionReport({
      generatedAt: "2026-05-27T00:00:00.000Z",
      checks: [{ name: "config-inventory", status: "failed", findings: [finding("critical", "mcp.config.dangerous_shell")] }]
    });

    expect(report.decision).toBe("deny");
    expect(report.summary.critical).toBe(1);
    expect(report.nextActions).toContain("Block this MCP server until critical findings are fixed.");
  });
});
