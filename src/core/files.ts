import { access, appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { AgentRunSchema, type AgentRun, type WatchtowerReport } from "./schemas.js";

export interface WatchtowerPaths {
  root: string;
  config: string;
  runsDir: string;
  runsJsonl: string;
  baselinesDir: string;
  mcpBaselineJson: string;
  reportsDir: string;
  reportMarkdown: string;
  reportHtml: string;
  reportJson: string;
  otelSpansJson: string;
  sarifJson: string;
  mcpBaselineDiffJson: string;
  mcpInventoryJson: string;
  mcpAdmissionJson: string;
  mcpGateJson: string;
  attackGraphJson: string;
  evidenceBundleJson: string;
}

export function getWatchtowerPaths(cwd: string): WatchtowerPaths {
  const root = join(cwd, ".watchtower");
  const runsDir = join(root, "runs");
  const baselinesDir = join(root, "baselines");
  const reportsDir = join(root, "reports");
  return {
    root,
    config: join(root, "config.json"),
    runsDir,
    runsJsonl: join(runsDir, "runs.jsonl"),
    baselinesDir,
    mcpBaselineJson: join(baselinesDir, "mcp-tools.json"),
    reportsDir,
    reportMarkdown: join(reportsDir, "watchtower-report.md"),
    reportHtml: join(reportsDir, "watchtower-report.html"),
    reportJson: join(reportsDir, "watchtower-report.json"),
    otelSpansJson: join(reportsDir, "otel-spans.json"),
    sarifJson: join(reportsDir, "watchtower.sarif"),
    mcpBaselineDiffJson: join(reportsDir, "mcp-baseline-diff.json"),
    mcpInventoryJson: join(reportsDir, "mcp-inventory.json"),
    mcpAdmissionJson: join(reportsDir, "mcp-admission.json"),
    mcpGateJson: join(reportsDir, "mcp-gate.json"),
    attackGraphJson: join(reportsDir, "attack-graph.json"),
    evidenceBundleJson: join(reportsDir, "evidence-bundle.json")
  };
}

export async function ensureWatchtowerDirs(cwd: string): Promise<WatchtowerPaths> {
  const paths = getWatchtowerPaths(cwd);
  await mkdir(paths.runsDir, { recursive: true });
  await mkdir(paths.baselinesDir, { recursive: true });
  await mkdir(paths.reportsDir, { recursive: true });
  return paths;
}

export async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

export async function writeJsonFile(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

export async function appendRunJsonl(path: string, run: AgentRun): Promise<void> {
  await appendFile(path, `${JSON.stringify(run)}\n`, "utf8");
}

export async function readRunsJsonl(path: string): Promise<AgentRun[]> {
  const content = await readFile(path, "utf8");
  return content
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line, index) => {
      try {
        return AgentRunSchema.parse(JSON.parse(line) as unknown);
      } catch (error) {
        const message = error instanceof Error ? error.message : "Unknown parse error";
        throw new Error(`Invalid stored run at ${path}:${index + 1}: ${message}`);
      }
    });
}

export async function writeReportFiles(paths: WatchtowerPaths, report: WatchtowerReport, markdown: string, html: string): Promise<void> {
  await writeJsonFile(paths.reportJson, report);
  await writeFile(paths.reportMarkdown, markdown, "utf8");
  await writeFile(paths.reportHtml, html, "utf8");
}
