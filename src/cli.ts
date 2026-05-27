#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { evaluateRuns } from "./core/evaluator.js";
import {
  appendRunJsonl,
  ensureWatchtowerDirs,
  fileExists,
  getWatchtowerPaths,
  readRunsJsonl,
  writeJsonFile,
  writeReportFiles
} from "./core/files.js";
import { importTraceFile } from "./core/importer.js";
import { scanMcpDescriptorFile } from "./core/mcpScanner.js";
import { createWatchtowerReport } from "./core/report.js";
import { renderHtmlReport, renderMarkdownReport } from "./core/reportRenderer.js";
import type { AgentRun, RiskFinding } from "./core/schemas.js";

export interface CliContext {
  cwd: string;
  stdout: (line: string) => void;
  stderr: (line: string) => void;
}

const currentFile = fileURLToPath(import.meta.url);
const packageRoot = resolve(dirname(currentFile), "..");

export function buildCli(context: Partial<CliContext> = {}): Command {
  const ctx: CliContext = {
    cwd: context.cwd ?? process.cwd(),
    stdout: context.stdout ?? ((line) => console.log(line)),
    stderr: context.stderr ?? ((line) => console.error(line))
  };

  const program = new Command();
  program
    .name("agentops-watchtower")
    .description("Local-first black box recorder, MCP safety scanner, and eval report generator for AI agent workflows.")
    .version("0.1.0");

  program
    .command("init")
    .description("Create local .watchtower config and storage folders.")
    .action(async () => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      if (await fileExists(paths.config)) {
        ctx.stdout(`Already initialized at ${paths.root}`);
        return;
      }

      await writeJsonFile(paths.config, {
        schemaVersion: 1,
        storage: "local-jsonl",
        runsFile: ".watchtower/runs/runs.jsonl",
        reportsDir: ".watchtower/reports",
        redaction: "enabled"
      });
      ctx.stdout(`Initialized AgentOps Watchtower at ${paths.root}`);
    });

  program
    .command("import")
    .argument("<trace>", "Path to a JSONL, NDJSON, Markdown, or text transcript.")
    .description("Import an agent transcript into normalized local JSONL storage.")
    .action(async (trace: string) => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const run = await importTraceFile(resolve(ctx.cwd, trace));
      await appendRunJsonl(paths.runsJsonl, run);
      await writeJsonFile(join(paths.runsDir, `${run.id}.json`), run);
      ctx.stdout(`Imported run ${run.id} with ${run.steps.length} steps and ${run.toolCalls.length} tool calls.`);
    });

  program
    .command("scan-mcp")
    .argument("[descriptor]", "Path to a JSON MCP descriptor file. Defaults to bundled example.")
    .description("Scan MCP tool descriptors for risky annotations, sensitive inputs, and missing schemas.")
    .action(async (descriptor?: string) => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const descriptorPath = descriptor === undefined ? bundledPath("examples", "mcp", "risky-tools.json") : resolve(ctx.cwd, descriptor);
      const result = await scanMcpDescriptorFile(descriptorPath);
      await writeJsonFile(join(paths.reportsDir, "mcp-scan.json"), result);
      ctx.stdout(`Scanned ${result.tools.length} MCP tools. Findings: ${result.findings.length}.`);
    });

  program
    .command("eval")
    .option("-t, --trace <trace>", "Import and evaluate a trace file instead of stored runs.")
    .description("Run deterministic eval checks against imported agent runs.")
    .action(async (options: { trace?: string }) => {
      const runs = await loadRunsForCommand(ctx.cwd, options.trace);
      const results = evaluateRuns(runs);
      const failed = results.filter((result) => !result.passed);
      ctx.stdout(`Eval results: ${results.length - failed.length}/${results.length} passed.`);
      for (const result of results) {
        ctx.stdout(`${result.passed ? "PASS" : "FAIL"} ${result.name}: ${result.message ?? ""}`);
      }
    });

  program
    .command("report")
    .option("-t, --trace <trace>", "Import this trace before generating the report.")
    .option("-m, --mcp <descriptor>", "Scan this MCP descriptor and include findings.")
    .description("Generate Markdown, HTML, and JSON reports from local runs and optional MCP scan findings.")
    .action(async (options: { trace?: string; mcp?: string }) => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const runs = await loadRunsForCommand(ctx.cwd, options.trace);
      const mcpFindings = await loadMcpFindings(ctx.cwd, options.mcp);
      const evalResults = evaluateRuns(runs);
      const report = createWatchtowerReport({
        runs,
        findings: [...runs.flatMap((run) => run.findings), ...mcpFindings],
        evalResults
      });
      await writeReportFiles(paths, report, renderMarkdownReport(report), renderHtmlReport(report));
      ctx.stdout(`Wrote ${paths.reportMarkdown}`);
      ctx.stdout(`Wrote ${paths.reportHtml}`);
    });

  program
    .command("demo")
    .description("Run a bundled local demo and generate Markdown plus HTML reports.")
    .action(async () => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const tracePath = bundledPath("examples", "traces", "codex-session.jsonl");
      const mcpPath = bundledPath("examples", "mcp", "risky-tools.json");
      const run = await importTraceFile(tracePath);
      const mcpScan = await scanMcpDescriptorFile(mcpPath);
      const evalResults = evaluateRuns([run]);
      const report = createWatchtowerReport({
        runs: [run],
        findings: [...run.findings, ...mcpScan.findings],
        evalResults
      });

      await appendRunJsonl(paths.runsJsonl, run);
      await writeJsonFile(join(paths.runsDir, `${run.id}.json`), run);
      await writeJsonFile(join(paths.reportsDir, "mcp-scan.json"), mcpScan);
      await writeReportFiles(paths, report, renderMarkdownReport(report), renderHtmlReport(report));
      ctx.stdout(`Demo complete. Risk score: ${report.summary.riskScore}.`);
      ctx.stdout(`Open ${paths.reportMarkdown} or ${paths.reportHtml}.`);
    });

  program
    .command("doctor")
    .description("Check Node version, local write access, and Watchtower config shape.")
    .action(async () => {
      const checks = await runDoctor(ctx.cwd);
      checks.forEach((check) => ctx.stdout(`${check.ok ? "PASS" : "FAIL"} ${check.name}: ${check.message}`));
      if (checks.some((check) => !check.ok)) {
        throw new Error("Doctor checks failed.");
      }
    });

  return program;
}

interface DoctorCheck {
  name: string;
  ok: boolean;
  message: string;
}

async function runDoctor(cwd: string): Promise<DoctorCheck[]> {
  const majorVersion = Number.parseInt(process.versions.node.split(".")[0] ?? "0", 10);
  const paths = getWatchtowerPaths(cwd);
  const tempDir = join(paths.root, "doctor");
  const tempFile = join(tempDir, "write-test.txt");
  const checks: DoctorCheck[] = [
    {
      name: "node",
      ok: majorVersion >= 22,
      message: `Node ${process.versions.node}`
    }
  ];

  try {
    await mkdir(tempDir, { recursive: true });
    await writeFile(tempFile, "ok", "utf8");
    checks.push({ name: "write-access", ok: true, message: paths.root });
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown error";
    checks.push({ name: "write-access", ok: false, message });
  }

  if (await fileExists(paths.config)) {
    try {
      const raw = JSON.parse(await readFile(paths.config, "utf8")) as unknown;
      const ok = isConfigRecord(raw);
      checks.push({ name: "config", ok, message: ok ? "config.json is valid enough for v0.1" : "config.json is malformed" });
    } catch (error) {
      const message = error instanceof Error ? error.message : "unknown error";
      checks.push({ name: "config", ok: false, message });
    }
  } else {
    checks.push({ name: "config", ok: true, message: "No config yet; run init to create one." });
  }

  return checks;
}

async function loadRunsForCommand(cwd: string, trace: string | undefined): Promise<AgentRun[]> {
  if (trace !== undefined) {
    return [await importTraceFile(resolve(cwd, trace))];
  }

  const paths = getWatchtowerPaths(cwd);
  if (!(await fileExists(paths.runsJsonl))) {
    return [await importTraceFile(bundledPath("examples", "traces", "codex-session.jsonl"))];
  }

  return readRunsJsonl(paths.runsJsonl);
}

async function loadMcpFindings(cwd: string, descriptor: string | undefined): Promise<RiskFinding[]> {
  if (descriptor === undefined) {
    return [];
  }

  const scan = await scanMcpDescriptorFile(resolve(cwd, descriptor));
  return scan.findings;
}

function bundledPath(...segments: string[]): string {
  return join(packageRoot, ...segments);
}

function isConfigRecord(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return record["schemaVersion"] === 1 && record["storage"] === "local-jsonl";
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === currentFile) {
  await buildCli().parseAsync(process.argv);
}
