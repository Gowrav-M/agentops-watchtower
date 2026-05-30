import { describe, expect, it } from "vitest";
import { getWatchtowerPaths } from "../src/core/files.js";
import { createWatchtowerTrustEvidence } from "../src/core/trustEvidence.js";
import type { WatchtowerReport } from "../src/core/schemas.js";

describe("Watchtower trust evidence", () => {
  it("maps critical runtime findings to a blocked trust decision", async () => {
    const report: WatchtowerReport = {
      generatedAt: "2026-05-30T00:00:00.000Z",
      summary: {
        runs: 1,
        toolCalls: 1,
        findings: 1,
        riskScore: 95
      },
      runs: [],
      findings: [
        {
          id: "runtime.secret-to-network",
          severity: "critical",
          category: "runtime.attack_path",
          title: "Secret reached external sink",
          description: "A local secret source was followed by an external network sink.",
          recommendation: "Block the workflow until the sink is removed.",
          target: "send_email"
        }
      ],
      evalResults: []
    };

    const evidence = await createWatchtowerTrustEvidence({
      paths: getWatchtowerPaths("D:\\tmp\\watchtower-evidence-test"),
      version: "1.6.0",
      report
    });

    expect(evidence.schemaVersion).toBe("agent.trust.evidence.v1");
    expect(evidence.subject.type).toBe("runtime");
    expect(evidence.decision).toBe("block");
    expect(evidence.score).toBe(95);
    expect(evidence.findings[0]?.severity).toBe("critical");
  });
});
