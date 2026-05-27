import type { AgentRun, EvalResult, RiskFinding, WatchtowerReport } from "./schemas.js";
import { WatchtowerReportSchema } from "./schemas.js";
import { calculateRiskScore } from "./risk.js";

export function createWatchtowerReport(input: {
  runs: readonly AgentRun[];
  findings: readonly RiskFinding[];
  evalResults: readonly EvalResult[];
  generatedAt?: string;
}): WatchtowerReport {
  const toolCalls = input.runs.reduce((total, run) => total + run.toolCalls.length, 0);
  const report = {
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    summary: {
      runs: input.runs.length,
      toolCalls,
      findings: input.findings.length,
      riskScore: calculateRiskScore(input.findings, input.evalResults)
    },
    runs: [...input.runs],
    findings: [...input.findings],
    evalResults: [...input.evalResults]
  };

  return WatchtowerReportSchema.parse(report);
}
