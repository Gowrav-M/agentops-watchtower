import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileExists, type WatchtowerPaths } from "./files.js";
import { WatchtowerReportSchema, type RiskFinding, type WatchtowerReport } from "./schemas.js";

export type TrustDecision = "allow" | "review" | "block";
export type TrustSeverity = "info" | "low" | "medium" | "warning" | "high" | "critical";

export interface TrustEvidenceFinding {
  id: string;
  severity: TrustSeverity;
  title: string;
  message: string;
  recommendation?: string;
  source?: string;
}

export interface TrustEvidence {
  schemaVersion: "agent.trust.evidence.v1";
  tool: {
    name: "agentops-watchtower";
    version: string;
  };
  subject: {
    type: "runtime";
    name: string;
  };
  decision: TrustDecision;
  score: number;
  generatedAt: string;
  findings: TrustEvidenceFinding[];
  artifacts: Array<{ type: string; path: string }>;
  recommendations: string[];
}

export function trustEvidencePath(paths: WatchtowerPaths): string {
  return join(paths.reportsDir, "trust-evidence.json");
}

export async function readWatchtowerReport(path: string): Promise<WatchtowerReport> {
  const raw = await readFile(path, "utf8");
  return WatchtowerReportSchema.parse(JSON.parse(raw) as unknown);
}

export async function createWatchtowerTrustEvidence(input: {
  paths: WatchtowerPaths;
  version: string;
  report?: WatchtowerReport;
}): Promise<TrustEvidence> {
  const report = input.report ?? await readWatchtowerReport(input.paths.reportJson);
  const findings = report.findings.map(toTrustFinding);
  const score = clampScore(report.summary.riskScore);
  const decision = decisionFor(report.findings, score);
  const artifacts = await existingArtifacts(input.paths);
  return {
    schemaVersion: "agent.trust.evidence.v1",
    tool: {
      name: "agentops-watchtower",
      version: input.version
    },
    subject: {
      type: "runtime",
      name: "agentops-watchtower local runtime evidence"
    },
    decision,
    score,
    generatedAt: report.generatedAt,
    findings,
    artifacts,
    recommendations: recommendationsFor(report.findings, decision)
  };
}

function decisionFor(findings: RiskFinding[], score: number): TrustDecision {
  if (findings.some((finding) => finding.severity === "critical") || score >= 80) {
    return "block";
  }
  if (findings.some((finding) => finding.severity === "high" || finding.severity === "medium") || score > 0) {
    return "review";
  }
  return "allow";
}

function toTrustFinding(finding: RiskFinding): TrustEvidenceFinding {
  const evidence: TrustEvidenceFinding = {
    id: finding.id,
    severity: finding.severity,
    title: finding.title,
    message: finding.description
  };
  if (finding.recommendation.length > 0) {
    evidence.recommendation = finding.recommendation;
  }
  if (finding.target !== undefined) {
    evidence.source = finding.target;
  }
  return evidence;
}

function recommendationsFor(findings: RiskFinding[], decision: TrustDecision): string[] {
  const recommendations = new Set<string>();
  for (const finding of findings) {
    if (finding.recommendation.length > 0) {
      recommendations.add(finding.recommendation);
    }
  }
  if (decision === "allow") {
    recommendations.add("Keep collecting runtime traces and rerun Watchtower before approving new agent tool chains.");
  }
  if (decision === "review") {
    recommendations.add("Review runtime findings before promoting this agent workflow.");
  }
  if (decision === "block") {
    recommendations.add("Block this workflow until critical Watchtower findings are resolved or explicitly accepted.");
  }
  return [...recommendations];
}

async function existingArtifacts(paths: WatchtowerPaths): Promise<Array<{ type: string; path: string }>> {
  const candidates: Array<{ type: string; path: string }> = [
    { type: "watchtower-report-json", path: paths.reportJson },
    { type: "watchtower-report-markdown", path: paths.reportMarkdown },
    { type: "watchtower-report-html", path: paths.reportHtml },
    { type: "attack-graph-json", path: paths.attackGraphJson },
    { type: "agent-bom-json", path: paths.agentBomJson },
    { type: "mcp-inventory-json", path: paths.mcpInventoryJson },
    { type: "evidence-bundle-json", path: paths.evidenceBundleJson },
    { type: "sarif", path: paths.sarifJson }
  ];
  const existing: Array<{ type: string; path: string }> = [];
  for (const candidate of candidates) {
    if (await fileExists(candidate.path)) {
      existing.push(candidate);
    }
  }
  return existing;
}

function clampScore(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}
