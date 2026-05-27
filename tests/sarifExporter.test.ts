import { describe, expect, it } from "vitest";
import { exportSarif } from "../src/core/sarifExporter.js";
import type { RiskFinding } from "../src/core/schemas.js";

describe("SARIF exporter", () => {
  it("exports findings as GitHub-compatible SARIF results", () => {
    const findings: RiskFinding[] = [
      {
        id: "finding-delete-repository-destructive",
        severity: "critical",
        category: "mcp.destructive_hint",
        title: "delete_repository appears destructive",
        description: "The tool can delete a repository.",
        recommendation: "Require explicit approval and mark destructiveHint true.",
        target: "delete_repository",
        evidence: ["delete_repository Delete a GitHub repository after confirmation."]
      }
    ];

    const sarif = exportSarif(findings, {
      sourceUri: "examples/mcp/risky-tools.json",
      invocationCommandLine: "agentops-watchtower scan-mcp examples/mcp/risky-tools.json --sarif"
    });

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(1);
    const [run] = sarif.runs;
    if (run === undefined) {
      throw new Error("Expected SARIF run.");
    }
    const [result] = run.results;
    if (result === undefined) {
      throw new Error("Expected SARIF result.");
    }

    expect(run.tool.driver.name).toBe("AgentOps Watchtower");
    expect(run.tool.driver.rules).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "mcp.destructive_hint",
          shortDescription: { text: "mcp.destructive_hint" }
        })
      ])
    );
    expect(result.ruleId).toBe("mcp.destructive_hint");
    expect(result.level).toBe("error");
    expect(result.message.text).toContain("delete_repository appears destructive");
    expect(result.partialFingerprints.watchtowerFindingId).toBe("finding-delete-repository-destructive");
    expect(result.locations?.[0]?.physicalLocation.artifactLocation.uri).toBe("examples/mcp/risky-tools.json");
  });
});
