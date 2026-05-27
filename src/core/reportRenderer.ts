import type { WatchtowerReport } from "./schemas.js";

export function renderMarkdownReport(report: WatchtowerReport): string {
  const lines: string[] = [
    "# AgentOps Watchtower Report",
    "",
    `Generated: ${report.generatedAt}`,
    "",
    "## Summary",
    "",
    `- Runs: ${report.summary.runs}`,
    `- Tool calls: ${report.summary.toolCalls}`,
    `- Findings: ${report.summary.findings}`,
    `- Risk score: ${report.summary.riskScore}`,
    "",
    "## Findings",
    ""
  ];

  if (report.findings.length === 0) {
    lines.push("No findings.");
  } else {
    lines.push("| Severity | Category | Target | Finding | Recommendation |");
    lines.push("| --- | --- | --- | --- | --- |");
    for (const finding of report.findings) {
      lines.push(
        `| ${finding.severity} | ${finding.category} | ${finding.target ?? "-"} | ${finding.title} | ${finding.recommendation} |`
      );
    }
  }

  lines.push("", "## Eval Results", "");

  for (const result of report.evalResults) {
    lines.push(`- ${result.passed ? "PASS" : "FAIL"} ${result.name}: ${result.message ?? ""}`.trim());
  }

  lines.push("", "## Run Timeline", "");

  for (const run of report.runs) {
    lines.push(`### ${run.id}`, "");
    if (run.goal !== undefined) {
      lines.push(`Goal: ${run.goal}`, "");
    }
    for (const step of run.steps) {
      lines.push(`- ${step.timestamp} [${step.status}] ${step.summary}`);
    }
    for (const toolCall of run.toolCalls) {
      lines.push(`- ${toolCall.timestamp} tool:${toolCall.toolName} status:${toolCall.status}`);
    }
    lines.push("");
  }

  return `${lines.join("\n").trimEnd()}\n`;
}

export function renderHtmlReport(report: WatchtowerReport): string {
  const findingRows =
    report.findings.length === 0
      ? "<p>No findings.</p>"
      : `<table><thead><tr><th>Severity</th><th>Category</th><th>Target</th><th>Finding</th><th>Recommendation</th></tr></thead><tbody>${report.findings
          .map(
            (finding) =>
              `<tr><td>${escapeHtml(finding.severity)}</td><td>${escapeHtml(finding.category)}</td><td>${escapeHtml(
                finding.target ?? "-"
              )}</td><td>${escapeHtml(finding.title)}</td><td>${escapeHtml(finding.recommendation)}</td></tr>`
          )
          .join("")}</tbody></table>`;

  const evalItems = report.evalResults
    .map(
      (result) =>
        `<li class="${result.passed ? "pass" : "fail"}">${result.passed ? "PASS" : "FAIL"} ${escapeHtml(
          result.name
        )}: ${escapeHtml(result.message ?? "")}</li>`
    )
    .join("");

  const timelines = report.runs
    .map((run) => {
      const steps = run.steps
        .map((step) => `<li>${escapeHtml(step.timestamp)} [${escapeHtml(step.status)}] ${escapeHtml(step.summary)}</li>`)
        .join("");
      const tools = run.toolCalls
        .map(
          (toolCall) =>
            `<li>${escapeHtml(toolCall.timestamp)} tool:${escapeHtml(toolCall.toolName)} status:${escapeHtml(
              toolCall.status
            )}</li>`
        )
        .join("");
      return `<section><h3>${escapeHtml(run.id)}</h3><p>${escapeHtml(run.goal ?? "")}</p><ul>${steps}${tools}</ul></section>`;
    })
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AgentOps Watchtower Report</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; color: #17202a; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #d8dee9; padding: 0.5rem; text-align: left; vertical-align: top; }
    th { background: #f5f7fa; }
    .score { font-size: 2rem; font-weight: 700; }
    .pass { color: #116329; }
    .fail { color: #9a3412; }
  </style>
</head>
<body>
  <h1>AgentOps Watchtower Report</h1>
  <p>Generated: ${escapeHtml(report.generatedAt)}</p>
  <section>
    <h2>Summary</h2>
    <p class="score">Risk score: ${report.summary.riskScore}</p>
    <p>Runs: ${report.summary.runs} | Tool calls: ${report.summary.toolCalls} | Findings: ${report.summary.findings}</p>
  </section>
  <section>
    <h2>Findings</h2>
    ${findingRows}
  </section>
  <section>
    <h2>Eval Results</h2>
    <ul>${evalItems}</ul>
  </section>
  <section>
    <h2>Run Timeline</h2>
    ${timelines}
  </section>
</body>
</html>
`;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
