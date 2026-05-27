#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { createAdmissionReport, type AdmissionCheck } from "./core/admission.js";
import { evaluateRuns } from "./core/evaluator.js";
import { createEvidenceBundle, readAdmissionDecision, verifyEvidenceBundle, type EvidenceArtifactInput } from "./core/evidence.js";
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
import { compareMcpBaseline, createMcpBaseline, readMcpBaselineFile } from "./core/mcpBaseline.js";
import { discoverMcpConfigCandidates, explicitMcpConfigCandidates, inventoryMcpConfigFiles } from "./core/mcpInventory.js";
import { scanMcpDescriptorFile, type McpScanOptions } from "./core/mcpScanner.js";
import { exportOtelSpans } from "./core/otelExporter.js";
import { loadWatchtowerConfig, shouldFailForFindings, summarizePolicyFailure } from "./core/policy.js";
import { createWatchtowerReport } from "./core/report.js";
import { renderHtmlReport, renderMarkdownReport } from "./core/reportRenderer.js";
import { exportSarif } from "./core/sarifExporter.js";
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
    .version("0.6.0");

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
        baselineFile: ".watchtower/baselines/mcp-tools.json",
        reportsDir: ".watchtower/reports",
        redaction: "enabled",
        policy: {
          failOn: "critical",
          requireOutputSchema: true,
          allowDestructiveTools: false,
          allowOpenWorldTools: true,
          detectToolPoisoning: true
        }
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
    .option("--fail-on <severity>", "Exit non-zero when findings meet this severity: info, low, medium, high, critical.")
    .option("--sarif", "Also write GitHub code scanning SARIF output.")
    .description("Scan MCP tool descriptors for risky annotations, sensitive inputs, and missing schemas.")
    .action(async (descriptor: string | undefined, options: { failOn?: string; sarif?: boolean }) => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const config = await loadWatchtowerConfig(ctx.cwd);
      const descriptorPath = descriptor === undefined ? bundledPath("examples", "mcp", "risky-tools.json") : resolve(ctx.cwd, descriptor);
      const result = await scanMcpDescriptorFile(descriptorPath, config.policy);
      await writeJsonFile(join(paths.reportsDir, "mcp-scan.json"), result);
      if (options.sarif === true) {
        await writeJsonFile(
          paths.sarifJson,
          exportSarif(result.findings, {
            sourceUri: sourceUri(ctx.cwd, descriptorPath),
            invocationCommandLine: `agentops-watchtower scan-mcp ${sourceUri(ctx.cwd, descriptorPath)} --sarif`
          })
        );
        ctx.stdout(`Wrote ${paths.sarifJson}`);
      }
      ctx.stdout(`Scanned ${result.tools.length} MCP tools. Findings: ${result.findings.length}.`);
      const failOn = parseSeverityOption(options.failOn) ?? config.policy.failOn;
      if (shouldFailForFindings(result.findings, failOn)) {
        throw new Error(summarizePolicyFailure(result.findings, failOn));
      }
    });

  program
    .command("baseline-mcp")
    .argument("<descriptor>", "Path to the approved MCP descriptor JSON.")
    .description("Create a local approved MCP tool fingerprint baseline.")
    .action(async (descriptor: string) => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const descriptorPath = resolve(ctx.cwd, descriptor);
      const result = await scanMcpDescriptorFile(descriptorPath);
      const baseline = createMcpBaseline(result.tools, {
        source: sourceUri(ctx.cwd, descriptorPath)
      });
      await writeJsonFile(paths.mcpBaselineJson, baseline);
      ctx.stdout(`Wrote MCP baseline for ${baseline.tools.length} tools to ${paths.mcpBaselineJson}`);
    });

  program
    .command("diff-mcp")
    .argument("<descriptor>", "Path to the current MCP descriptor JSON.")
    .option("-b, --baseline <baseline>", "Path to a Watchtower MCP baseline file.")
    .option("--fail-on <severity>", "Exit non-zero when baseline drift findings meet this severity.")
    .option("--sarif", "Also write GitHub code scanning SARIF output.")
    .description("Compare current MCP tools against an approved baseline to detect tool drift.")
    .action(async (descriptor: string, options: { baseline?: string; failOn?: string; sarif?: boolean }) => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const descriptorPath = resolve(ctx.cwd, descriptor);
      const baselinePath = options.baseline === undefined ? paths.mcpBaselineJson : resolve(ctx.cwd, options.baseline);
      const baseline = await readMcpBaselineFile(baselinePath);
      const currentScan = await scanMcpDescriptorFile(descriptorPath);
      const diff = compareMcpBaseline(baseline, currentScan.tools);
      await writeJsonFile(paths.mcpBaselineDiffJson, diff);
      if (options.sarif === true) {
        await writeJsonFile(
          paths.sarifJson,
          exportSarif(diff.findings, {
            sourceUri: sourceUri(ctx.cwd, descriptorPath),
            invocationCommandLine: `agentops-watchtower diff-mcp ${sourceUri(ctx.cwd, descriptorPath)} --sarif`
          })
        );
        ctx.stdout(`Wrote ${paths.sarifJson}`);
      }
      ctx.stdout(`Compared ${diff.current.tools.length} MCP tools against baseline. Findings: ${diff.findings.length}.`);
      const failOn = parseSeverityOption(options.failOn) ?? "critical";
      if (shouldFailForFindings(diff.findings, failOn)) {
        throw new Error(summarizePolicyFailure(diff.findings, failOn));
      }
    });

  program
    .command("inventory-mcp")
    .argument("[configs...]", "Optional MCP config files. If omitted, Watchtower scans common local client config paths.")
    .option("--fail-on <severity>", "Exit non-zero when inventory findings meet this severity.")
    .option("--sarif", "Also write GitHub code scanning SARIF output.")
    .description("Inventory local MCP client configuration and flag risky server launch settings.")
    .action(async (configs: string[], options: { failOn?: string; sarif?: boolean }) => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const config = await loadWatchtowerConfig(ctx.cwd);
      const home = process.env["USERPROFILE"] ?? process.env["HOME"];
      const appData = process.env["APPDATA"];
      const candidates =
        configs.length > 0
          ? explicitMcpConfigCandidates(configs.map((configPath) => resolve(ctx.cwd, configPath)))
          : discoverMcpConfigCandidates({
              cwd: ctx.cwd,
              ...(home === undefined ? {} : { home }),
              ...(appData === undefined ? {} : { appData })
            });
      const inventory = await inventoryMcpConfigFiles(candidates);
      await writeJsonFile(paths.mcpInventoryJson, inventory);
      if (options.sarif === true) {
        await writeJsonFile(
          paths.sarifJson,
          exportSarif(inventory.findings, {
            ...(configs.length === 1 ? { sourceUri: sourceUri(ctx.cwd, resolve(ctx.cwd, configs[0] ?? "")) } : {}),
            invocationCommandLine: `agentops-watchtower inventory-mcp${configs.length === 0 ? "" : ` ${configs.join(" ")}`} --sarif`
          })
        );
        ctx.stdout(`Wrote ${paths.sarifJson}`);
      }
      ctx.stdout(`Inventoried ${inventory.servers.length} MCP servers from ${inventory.sources.length} candidate config files.`);
      ctx.stdout(`Findings: ${inventory.findings.length}.`);
      const failOn = parseSeverityOption(options.failOn) ?? config.policy.failOn;
      if (shouldFailForFindings(inventory.findings, failOn)) {
        throw new Error(summarizePolicyFailure(inventory.findings, failOn));
      }
    });

  program
    .command("admit-mcp")
    .option("-d, --descriptor <descriptor>", "MCP descriptor JSON to scan before admission.")
    .option("-c, --config <config...>", "MCP client config file(s) to inventory before admission.")
    .option("-b, --baseline <baseline>", "Optional Watchtower MCP baseline file for drift checks.")
    .option("--fail-on <severity>", "Exit non-zero when admission findings meet this severity.")
    .option("--sarif", "Also write GitHub code scanning SARIF output.")
    .description("Create an MCP admission decision from config inventory, descriptor scan, and optional baseline drift.")
    .action(async (options: { descriptor?: string; config?: string[]; baseline?: string; failOn?: string; sarif?: boolean }) => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const config = await loadWatchtowerConfig(ctx.cwd);
      const checks: AdmissionCheck[] = [];

      if (options.config !== undefined && options.config.length > 0) {
        const inventory = await inventoryMcpConfigFiles(
          explicitMcpConfigCandidates(options.config.map((configPath) => resolve(ctx.cwd, configPath)))
        );
        await writeJsonFile(paths.mcpInventoryJson, inventory);
        checks.push({
          name: "config-inventory",
          status: inventory.findings.length === 0 ? "passed" : "failed",
          findings: inventory.findings
        });
      } else {
        checks.push({ name: "config-inventory", status: "skipped", findings: [] });
      }

      if (options.descriptor !== undefined) {
        const descriptorPath = resolve(ctx.cwd, options.descriptor);
        const descriptorScan = await scanMcpDescriptorFile(descriptorPath, config.policy);
        await writeJsonFile(join(paths.reportsDir, "mcp-scan.json"), descriptorScan);
        checks.push({
          name: "descriptor-scan",
          status: descriptorScan.findings.length === 0 ? "passed" : "failed",
          findings: descriptorScan.findings
        });

        const baselinePath = options.baseline === undefined ? paths.mcpBaselineJson : resolve(ctx.cwd, options.baseline);
        if (await fileExists(baselinePath)) {
          const baseline = await readMcpBaselineFile(baselinePath);
          const diff = compareMcpBaseline(baseline, descriptorScan.tools);
          await writeJsonFile(paths.mcpBaselineDiffJson, diff);
          checks.push({
            name: "baseline-diff",
            status: diff.findings.length === 0 ? "passed" : "failed",
            findings: diff.findings
          });
        } else {
          checks.push({ name: "baseline-diff", status: "skipped", findings: [] });
        }
      } else {
        checks.push({ name: "descriptor-scan", status: "skipped", findings: [] });
        checks.push({ name: "baseline-diff", status: "skipped", findings: [] });
      }

      const admission = createAdmissionReport({ checks });
      await writeJsonFile(paths.mcpAdmissionJson, admission);
      if (options.sarif === true) {
        await writeJsonFile(
          paths.sarifJson,
          exportSarif(admission.findings, {
            ...(options.descriptor === undefined ? {} : { sourceUri: sourceUri(ctx.cwd, resolve(ctx.cwd, options.descriptor)) }),
            invocationCommandLine: "agentops-watchtower admit-mcp --sarif"
          })
        );
        ctx.stdout(`Wrote ${paths.sarifJson}`);
      }
      ctx.stdout(`Admission decision: ${admission.decision}`);
      ctx.stdout(`Findings: ${admission.summary.findings}.`);
      const failOn = parseSeverityOption(options.failOn) ?? "critical";
      if (shouldFailForFindings(admission.findings, failOn)) {
        throw new Error(summarizePolicyFailure(admission.findings, failOn));
      }
    });

  program
    .command("attest-mcp")
    .option("--subject <subject>", "Human-readable subject for the evidence bundle.")
    .description("Create a tamper-evident evidence bundle from Watchtower MCP reports.")
    .action(async (options: { subject?: string }) => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const artifacts = await existingEvidenceArtifacts(paths);
      if (artifacts.length === 0) {
        throw new Error("No Watchtower MCP report artifacts found. Run admit-mcp, scan-mcp, inventory-mcp, or diff-mcp first.");
      }
      const admissionDecision = await readAdmissionDecision(paths.mcpAdmissionJson);
      const bundle = await createEvidenceBundle({
        cwd: ctx.cwd,
        ...(options.subject === undefined ? {} : { subject: options.subject }),
        ...(admissionDecision === undefined ? {} : { admissionDecision }),
        artifacts
      });
      await writeJsonFile(paths.evidenceBundleJson, bundle);
      ctx.stdout(`Wrote evidence bundle to ${paths.evidenceBundleJson}`);
      ctx.stdout(`Integrity hash: ${bundle.integrityHash}`);
    });

  program
    .command("verify-attestation")
    .argument("[bundle]", "Evidence bundle path. Defaults to .watchtower/reports/evidence-bundle.json.")
    .description("Verify a Watchtower evidence bundle against current local artifacts.")
    .action(async (bundle: string | undefined) => {
      const paths = getWatchtowerPaths(ctx.cwd);
      const bundlePath = bundle === undefined ? paths.evidenceBundleJson : resolve(ctx.cwd, bundle);
      const evidence = JSON.parse(await readFile(bundlePath, "utf8")) as Awaited<ReturnType<typeof createEvidenceBundle>>;
      const verification = await verifyEvidenceBundle(evidence, ctx.cwd);
      if (!verification.ok) {
        throw new Error(`Evidence bundle verification failed: ${verification.failures.join("; ")}`);
      }
      ctx.stdout("Evidence bundle verified.");
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
    .option("--fail-on <severity>", "Exit non-zero when report findings meet this severity.")
    .description("Generate Markdown, HTML, and JSON reports from local runs and optional MCP scan findings.")
    .action(async (options: { trace?: string; mcp?: string; failOn?: string }) => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const config = await loadWatchtowerConfig(ctx.cwd);
      const runs = await loadRunsForCommand(ctx.cwd, options.trace);
      const mcpFindings = await loadMcpFindings(ctx.cwd, options.mcp, config.policy);
      const evalResults = evaluateRuns(runs);
      const report = createWatchtowerReport({
        runs,
        findings: [...runs.flatMap((run) => run.findings), ...mcpFindings],
        evalResults
      });
      await writeReportFiles(paths, report, renderMarkdownReport(report), renderHtmlReport(report));
      ctx.stdout(`Wrote ${paths.reportMarkdown}`);
      ctx.stdout(`Wrote ${paths.reportHtml}`);
      const failOn = parseSeverityOption(options.failOn) ?? config.policy.failOn;
      if (shouldFailForFindings(report.findings, failOn)) {
        throw new Error(summarizePolicyFailure(report.findings, failOn));
      }
    });

  program
    .command("export-otel")
    .option("-t, --trace <trace>", "Export this trace instead of stored runs.")
    .description("Export local agent runs as OpenTelemetry-style GenAI/MCP span JSON.")
    .action(async (options: { trace?: string }) => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const runs = await loadRunsForCommand(ctx.cwd, options.trace);
      const spans = exportOtelSpans(runs);
      await writeJsonFile(paths.otelSpansJson, spans);
      ctx.stdout(`Wrote ${spans.length} OTel-style spans to ${paths.otelSpansJson}`);
    });

  program
    .command("demo")
    .description("Run a bundled local demo and generate Markdown plus HTML reports.")
    .action(async () => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const tracePath = bundledPath("examples", "traces", "codex-session.jsonl");
      const mcpPath = bundledPath("examples", "mcp", "risky-tools.json");
      const safeMcpPath = bundledPath("examples", "mcp", "safe-tools.json");
      const run = await importTraceFile(tracePath);
      const mcpScan = await scanMcpDescriptorFile(mcpPath);
      const safeMcpScan = await scanMcpDescriptorFile(safeMcpPath);
      const evalResults = evaluateRuns([run]);
      const report = createWatchtowerReport({
        runs: [run],
        findings: [...run.findings, ...mcpScan.findings],
        evalResults
      });

      await appendRunJsonl(paths.runsJsonl, run);
      await writeJsonFile(join(paths.runsDir, `${run.id}.json`), run);
      await writeJsonFile(join(paths.reportsDir, "mcp-scan.json"), mcpScan);
      await writeJsonFile(paths.mcpBaselineJson, createMcpBaseline(safeMcpScan.tools, { source: "examples/mcp/safe-tools.json" }));
      await writeJsonFile(paths.sarifJson, exportSarif(mcpScan.findings, { sourceUri: "examples/mcp/risky-tools.json" }));
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
      checks.push({ name: "config", ok, message: ok ? "config.json is valid enough for v0.3" : "config.json is malformed" });
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

async function loadMcpFindings(
  cwd: string,
  descriptor: string | undefined,
  options: McpScanOptions
): Promise<RiskFinding[]> {
  if (descriptor === undefined) {
    return [];
  }

  const scan = await scanMcpDescriptorFile(resolve(cwd, descriptor), options);
  return scan.findings;
}

function bundledPath(...segments: string[]): string {
  return join(packageRoot, ...segments);
}

function sourceUri(cwd: string, path: string): string {
  const relativePath = relative(cwd, path);
  return (relativePath.startsWith("..") ? path : relativePath).replaceAll("\\", "/");
}

async function existingEvidenceArtifacts(paths: ReturnType<typeof getWatchtowerPaths>): Promise<EvidenceArtifactInput[]> {
  const candidates: EvidenceArtifactInput[] = [
    { name: "mcp-admission", path: paths.mcpAdmissionJson },
    { name: "mcp-inventory", path: paths.mcpInventoryJson },
    { name: "mcp-scan", path: join(paths.reportsDir, "mcp-scan.json") },
    { name: "mcp-baseline-diff", path: paths.mcpBaselineDiffJson },
    { name: "watchtower-sarif", path: paths.sarifJson },
    { name: "watchtower-report", path: paths.reportJson }
  ];
  const existing: EvidenceArtifactInput[] = [];
  for (const candidate of candidates) {
    if (await fileExists(candidate.path)) {
      existing.push(candidate);
    }
  }
  return existing;
}

function isConfigRecord(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return record["schemaVersion"] === 1 && record["storage"] === "local-jsonl";
}

function parseSeverityOption(value: string | undefined): RiskFinding["severity"] | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (value === "info" || value === "low" || value === "medium" || value === "high" || value === "critical") {
    return value;
  }

  throw new Error(`Invalid severity threshold: ${value}`);
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === currentFile) {
  try {
    await buildCli().parseAsync(process.argv);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
