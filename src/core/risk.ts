import type { EvalResult, RiskFinding, Severity } from "./schemas.js";

const SEVERITY_WEIGHT: Record<Severity, number> = {
  info: 1,
  low: 5,
  medium: 10,
  high: 20,
  critical: 35
};

export function calculateRiskScore(findings: readonly RiskFinding[], evalResults: readonly EvalResult[] = []): number {
  const findingScore = findings.reduce((total, finding) => total + SEVERITY_WEIGHT[finding.severity], 0);
  const evalScore = evalResults.reduce((total, result) => {
    if (result.passed) {
      return total;
    }
    return total + Math.ceil(SEVERITY_WEIGHT[result.severity] / 2);
  }, 0);

  return Math.min(100, findingScore + evalScore);
}

export function createFinding(input: Omit<RiskFinding, "id"> & { idSeed: string }): RiskFinding {
  const safeSeed = input.idSeed
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");

  return {
    id: `finding-${safeSeed}`,
    severity: input.severity,
    category: input.category,
    title: input.title,
    description: input.description,
    recommendation: input.recommendation,
    ...(input.target === undefined ? {} : { target: input.target }),
    ...(input.evidence === undefined ? {} : { evidence: input.evidence })
  };
}
