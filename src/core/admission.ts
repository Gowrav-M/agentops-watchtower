import type { RiskFinding, Severity } from "./schemas.js";

export type AdmissionDecision = "allow" | "review" | "deny";
export type AdmissionCheckName = "config-inventory" | "descriptor-scan" | "baseline-diff";
export type AdmissionCheckStatus = "passed" | "failed" | "skipped";

export interface AdmissionCheck {
  name: AdmissionCheckName;
  status: AdmissionCheckStatus;
  findings: RiskFinding[];
}

export interface AdmissionReport {
  schemaVersion: 1;
  generatedAt: string;
  decision: AdmissionDecision;
  summary: {
    checks: number;
    passed: number;
    failed: number;
    skipped: number;
    findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  checks: AdmissionCheck[];
  findings: RiskFinding[];
  nextActions: string[];
}

export interface CreateAdmissionReportInput {
  generatedAt?: string;
  checks: AdmissionCheck[];
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export function createAdmissionReport(input: CreateAdmissionReportInput): AdmissionReport {
  const findings = input.checks.flatMap((check) => check.findings).sort((left, right) => left.id.localeCompare(right.id));
  const counts = countSeverities(findings);
  const decision = decideAdmission(counts);

  return {
    schemaVersion: 1,
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    decision,
    summary: {
      checks: input.checks.length,
      passed: input.checks.filter((check) => check.status === "passed").length,
      failed: input.checks.filter((check) => check.status === "failed").length,
      skipped: input.checks.filter((check) => check.status === "skipped").length,
      findings: findings.length,
      critical: counts.critical,
      high: counts.high,
      medium: counts.medium,
      low: counts.low,
      info: counts.info
    },
    checks: input.checks,
    findings,
    nextActions: nextActionsForDecision(decision)
  };
}

function decideAdmission(counts: Record<Severity, number>): AdmissionDecision {
  if (counts.critical > 0) {
    return "deny";
  }
  if (counts.high > 0 || counts.medium > 0) {
    return "review";
  }
  return "allow";
}

function countSeverities(findings: readonly RiskFinding[]): Record<Severity, number> {
  const counts = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0])) as Record<Severity, number>;
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  return counts;
}

function nextActionsForDecision(decision: AdmissionDecision): string[] {
  if (decision === "deny") {
    return [
      "Block this MCP server until critical findings are fixed.",
      "Re-run admission after updating config, descriptors, or the approved baseline."
    ];
  }

  if (decision === "review") {
    return [
      "Require human security review before enabling this MCP server.",
      "Pin packages, remove secrets, and document external or destructive capabilities."
    ];
  }

  return ["Allow MCP server only within the reviewed scope.", "Re-run admission whenever config or descriptor files change."];
}
