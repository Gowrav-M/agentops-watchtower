#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { createAdmissionReport, type AdmissionCheck } from "./core/admission.js";
import { createAgentBom, exportCycloneDxAgentBom, renderAgentBomMarkdown } from "./core/agentBom.js";
import { analyzeRuns, type AttackGraphContext } from "./core/attackGraph.js";
import { evaluateRuns } from "./core/evaluator.js";
import { createEvidenceBundle, readAdmissionDecision, signEvidenceBundle, verifyEvidenceBundle, type EvidenceArtifactInput } from "./core/evidence.js";
import { createFirewallConfigFromTools, readFirewallConfigFile, simulateFirewall } from "./core/firewall.js";
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
import { createMcpGateReport } from "./core/mcpGate.js";
import { discoverMcpConfigCandidates, explicitMcpConfigCandidates, inventoryMcpConfigFiles } from "./core/mcpInventory.js";
import { createMcpProtection, restoreMcpProtection, type McpProtectionManifest } from "./core/mcpProtect.js";
import { createMcpProxyAuditReport, createMcpProxyState, runStdioMcpProxy } from "./core/mcpProxy.js";
import { scanMcpDescriptorFile, type McpScanOptions } from "./core/mcpScanner.js";
import { exportOtelSpans } from "./core/otelExporter.js";
import { loadWatchtowerConfig, shouldFailForFindings, summarizePolicyFailure } from "./core/policy.js";
import { createWatchtowerReport } from "./core/report.js";
import { renderHtmlReport, renderMarkdownReport } from "./core/reportRenderer.js";
import { exportSarif } from "./core/sarifExporter.js";
import type { AgentRun, RiskFinding } from "./core/schemas.js";
import { createWatchtowerTrustEvidence, trustEvidencePath } from "./core/trustEvidence.js";

export interface CliContext {
  cwd: string;
  stdout: (line: string) => void;
  stderr: (line: string) => void;
}

const currentFile = fileURLToPath(import.meta.url);
const packageRoot = resolve(dirname(currentFile), "..");
const advancedCommandList = [
  "scan-mcp",
  "baseline-mcp",
  "diff-mcp",
  "inventory-mcp",
  "admit-mcp",
  "gate-mcp",
  "firewall",
  "proxy-mcp",
  "protect-mcp",
  "agent-bom",
  "analyze-run",
  "export-otel",
  "attest-mcp"
];

interface LocalWatchtowerConfigFile {
  schemaVersion: 1;
  storage: "local-jsonl";
  runsFile: string;
  baselineFile: string;
  reportsDir: string;
  redaction: "enabled";
  policy: {
    failOn: "critical";
    requireOutputSchema: true;
    allowDestructiveTools: false;
    allowOpenWorldTools: true;
    detectToolPoisoning: true;
  };
}

interface InitializeWatchtowerResult {
  paths: ReturnType<typeof getWatchtowerPaths>;
  created: boolean;
}

interface ProtectMcpCommandOptions {
  config: string;
  server: string;
  out?: string;
  inPlace?: boolean;
  descriptor?: string;
  baseline?: string;
  firewall?: string;
  failOn?: string;
  package?: string;
}

interface ProtectMcpCommandResult {
  protectedConfigPath: string;
  manifestPath: string;
  backupConfigPath?: string;
}

function readPackageVersion(): string {
  const packageJson = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8")) as { version?: unknown };
  if (typeof packageJson.version !== "string") {
    throw new Error("package.json version is missing.");
  }
  return packageJson.version;
}

export function buildCli(context: Partial<CliContext> = {}): Command {
  const ctx: CliContext = {
    cwd: context.cwd ?? process.cwd(),
    stdout: context.stdout ?? ((line) => console.log(line)),
    stderr: context.stderr ?? ((line) => console.error(line))
  };

  const program = new Command();
  program
    .name("agentops-watchtower")
    .description("Local-first black box recorder, MCP safety scanner, runtime Capability Firewall, and evidence generator.")
    .version(readPackageVersion());

  program
    .command("init")
    .description("Create local .watchtower config and storage folders.")
    .action(async () => {
      const result = await initializeWatchtower(ctx.cwd);
      if (!result.created) {
        ctx.stdout(`Already initialized at ${result.paths.root}`);
        return;
      }

      ctx.stdout(`Initialized AgentOps Watchtower at ${result.paths.root}`);
    });

  program
    .command("setup")
    .option("-d, --descriptor <descriptor>", "MCP descriptor JSON to use for the starter scan and firewall policy.")
    .option("--skip-slash-commands", "Do not write local slash-command templates.")
    .description("One-command local setup: config, starter MCP scan, firewall policy, and slash-command templates.")
    .action(async (options: { descriptor?: string; skipSlashCommands?: boolean }) => {
      const setup = await runSetup(ctx, options);
      ctx.stdout(`Setup complete. ${setup.configCreated ? "Created" : "Reused"} ${setup.paths.config}`);
      ctx.stdout(`Wrote MCP scan to ${join(setup.paths.reportsDir, "mcp-scan.json")}`);
      ctx.stdout(`Wrote firewall policy to ${setup.paths.firewallConfigJson}`);
      if (setup.slashCommandsWritten > 0) {
        ctx.stdout(`Wrote ${setup.slashCommandsWritten} slash-command templates to ${setup.paths.slashCommandsDir}`);
      }
      ctx.stdout(`Advanced commands remain available: ${advancedCommandList.join(", ")}.`);
    });

  program
    .command("check")
    .option("-d, --descriptor <descriptor>", "MCP descriptor JSON to scan and use as runtime context.")
    .option("-m, --mcp <descriptor>", "Alias for --descriptor.")
    .option("-c, --config <config...>", "Optional MCP client config file(s) to inventory and use as context.")
    .option("-t, --trace <trace>", "Trace file to analyze. Defaults to stored runs or the bundled sample trace.")
    .option("--firewall <firewall>", "Capability Firewall policy to simulate against the trace.")
    .option("--sarif", "Also write GitHub code scanning SARIF output for combined findings.")
    .option("--fail-on <severity>", "Exit non-zero when combined findings meet this severity.")
    .description("One-command assessment: scan, runtime attack graph, optional firewall replay, and report.")
    .action(
      async (options: {
        descriptor?: string;
        mcp?: string;
        config?: string[];
        trace?: string;
        firewall?: string;
        sarif?: boolean;
        failOn?: string;
      }) => {
        const result = await runCombinedCheck(ctx, options);
        ctx.stdout(`Watchtower check complete. Risk score: ${result.report.summary.riskScore}. Findings: ${result.report.findings.length}.`);
        ctx.stdout(`Reports: ${result.paths.reportMarkdown} and ${result.paths.reportHtml}`);
        ctx.stdout(`Advanced artifacts: ${result.artifacts.join(", ")}.`);
      }
    );

  program
    .command("protect")
    .requiredOption("-c, --config <config>", "MCP client JSON config to protect.")
    .requiredOption("-s, --server <server>", "MCP server name to route through the Watchtower proxy.")
    .option("-o, --out <out>", "Protected config output path.")
    .option("--in-place", "Modify the original config after writing a backup and rollback manifest.")
    .option("-d, --descriptor <descriptor>", "MCP descriptor JSON to pass through to proxy-mcp.")
    .option("-b, --baseline <baseline>", "Watchtower MCP baseline file to pass through to proxy-mcp.")
    .option("--firewall <firewall>", "Capability Firewall policy config to pass through to proxy-mcp.")
    .option("--fail-on <severity>", "Proxy policy threshold to pass through to proxy-mcp.")
    .option("--package <packageSpec>", "npm package spec used in the protected npx wrapper.")
    .description("Simple shortcut for protecting one MCP server while keeping protect-mcp available for full control.")
    .action(async (options: ProtectMcpCommandOptions) => {
      const result = await runMcpProtection(ctx, options);
      if (result.backupConfigPath !== undefined) {
        ctx.stdout(`Backup written to ${result.backupConfigPath}`);
      }
      ctx.stdout(`Protected config written to ${result.protectedConfigPath}`);
      ctx.stdout(`Protection manifest written to ${result.manifestPath}`);
      ctx.stdout("Advanced equivalent: agentops-watchtower protect-mcp with the same flags.");
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
    .command("gate-mcp")
    .requiredOption("-c, --config <config...>", "MCP client config file(s) to inventory before the gate decision.")
    .option("-s, --server <server>", "MCP server name or full inventory id to gate. Required when the config has multiple servers.")
    .option("-d, --descriptor <descriptor>", "MCP descriptor JSON to scan before the gate decision.")
    .option("-b, --baseline <baseline>", "Optional Watchtower MCP baseline file for drift checks.")
    .option("--allow-review", "Allow a review decision to produce a dry-run launch plan after human approval.")
    .option("--fail-on <severity>", "Exit non-zero when gate findings meet this severity.")
    .option("--sarif", "Also write GitHub code scanning SARIF output.")
    .description("Preflight an MCP server from local config and block unsafe launch plans.")
    .action(
      async (options: {
        config: string[];
        server?: string;
        descriptor?: string;
        baseline?: string;
        allowReview?: boolean;
        failOn?: string;
        sarif?: boolean;
      }) => {
        const paths = await ensureWatchtowerDirs(ctx.cwd);
        const watchtowerConfig = await loadWatchtowerConfig(ctx.cwd);
        const inventory = await inventoryMcpConfigFiles(
          explicitMcpConfigCandidates(options.config.map((configPath) => resolve(ctx.cwd, configPath)))
        );
        await writeJsonFile(paths.mcpInventoryJson, inventory);

        let descriptorFindings: RiskFinding[] | undefined;
        let baselineFindings: RiskFinding[] | undefined;
        if (options.descriptor !== undefined) {
          const descriptorPath = resolve(ctx.cwd, options.descriptor);
          const descriptorScan = await scanMcpDescriptorFile(descriptorPath, watchtowerConfig.policy);
          descriptorFindings = descriptorScan.findings;
          await writeJsonFile(join(paths.reportsDir, "mcp-scan.json"), descriptorScan);

          const baselinePath = options.baseline === undefined ? paths.mcpBaselineJson : resolve(ctx.cwd, options.baseline);
          if (await fileExists(baselinePath)) {
            const baseline = await readMcpBaselineFile(baselinePath);
            const diff = compareMcpBaseline(baseline, descriptorScan.tools);
            baselineFindings = diff.findings;
            await writeJsonFile(paths.mcpBaselineDiffJson, diff);
          }
        } else if (options.baseline !== undefined) {
          throw new Error("gate-mcp requires --descriptor when --baseline is provided.");
        }

        const gate = createMcpGateReport({
          inventory,
          ...(options.server === undefined ? {} : { serverName: options.server }),
          ...(descriptorFindings === undefined ? {} : { descriptorFindings }),
          ...(baselineFindings === undefined ? {} : { baselineFindings }),
          allowReview: options.allowReview === true
        });
        await writeJsonFile(paths.mcpGateJson, gate);

        if (options.sarif === true) {
          await writeJsonFile(
            paths.sarifJson,
            exportSarif(gate.admission.findings, {
              ...(options.config.length === 1 ? { sourceUri: sourceUri(ctx.cwd, resolve(ctx.cwd, options.config[0] ?? "")) } : {}),
              invocationCommandLine: "agentops-watchtower gate-mcp --sarif"
            })
          );
          ctx.stdout(`Wrote ${paths.sarifJson}`);
        }

        ctx.stdout(`Gate decision: ${gate.admission.decision}`);
        ctx.stdout(`Launch mode: ${gate.launch.mode}`);
        ctx.stdout(`Wrote ${paths.mcpGateJson}`);

        const failOn = parseSeverityOption(options.failOn) ?? watchtowerConfig.policy.failOn;
        if (shouldFailForFindings(gate.admission.findings, failOn)) {
          throw new Error(summarizePolicyFailure(gate.admission.findings, failOn));
        }
        if (gate.launch.mode === "blocked") {
          throw new Error(`MCP gate blocked launch: ${gate.launch.reason}`);
        }
      }
    );

  program
    .command("proxy-mcp")
    .requiredOption("-c, --config <config...>", "MCP client config file(s) containing the stdio server to proxy.")
    .option("-s, --server <server>", "MCP server name or full inventory id to proxy. Required when the config has multiple servers.")
    .option("-d, --descriptor <descriptor>", "MCP descriptor JSON to use for gate checks and runtime policy context.")
    .option("-b, --baseline <baseline>", "Optional Watchtower MCP baseline file for drift checks.")
    .option("--firewall <firewall>", "Capability Firewall policy config to enforce on MCP tool calls.")
    .option("--allow-review", "Allow a review gate decision after human approval.")
    .option("--fail-on <severity>", "Exit non-zero when proxy preflight findings meet this severity.")
    .option("--dry-run", "Run the preflight gate and write an empty proxy audit without launching the server.")
    .description("Run a local stdio MCP policy proxy that can block unsafe tool calls before execution.")
    .action(
      async (options: {
        config: string[];
        server?: string;
        descriptor?: string;
        baseline?: string;
        firewall?: string;
        allowReview?: boolean;
        failOn?: string;
        dryRun?: boolean;
      }) => {
        const paths = await ensureWatchtowerDirs(ctx.cwd);
        const watchtowerConfig = await loadWatchtowerConfig(ctx.cwd);
        const inventory = await inventoryMcpConfigFiles(
          explicitMcpConfigCandidates(options.config.map((configPath) => resolve(ctx.cwd, configPath)))
        );
        await writeJsonFile(paths.mcpInventoryJson, inventory);

        let descriptorFindings: RiskFinding[] | undefined;
        let baselineFindings: RiskFinding[] | undefined;
        let descriptorTools: Awaited<ReturnType<typeof scanMcpDescriptorFile>>["tools"] | undefined;
        const firewall = options.firewall === undefined ? undefined : await readFirewallConfigFile(resolve(ctx.cwd, options.firewall));
        if (options.descriptor !== undefined) {
          const descriptorPath = resolve(ctx.cwd, options.descriptor);
          const descriptorScan = await scanMcpDescriptorFile(descriptorPath, watchtowerConfig.policy);
          descriptorTools = descriptorScan.tools;
          descriptorFindings = descriptorScan.findings;
          await writeJsonFile(join(paths.reportsDir, "mcp-scan.json"), descriptorScan);

          const baselinePath = options.baseline === undefined ? paths.mcpBaselineJson : resolve(ctx.cwd, options.baseline);
          if (await fileExists(baselinePath)) {
            const baseline = await readMcpBaselineFile(baselinePath);
            const diff = compareMcpBaseline(baseline, descriptorScan.tools);
            baselineFindings = diff.findings;
            await writeJsonFile(paths.mcpBaselineDiffJson, diff);
          }
        } else if (options.baseline !== undefined) {
          throw new Error("proxy-mcp requires --descriptor when --baseline is provided.");
        }

        const gate = createMcpGateReport({
          inventory,
          ...(options.server === undefined ? {} : { serverName: options.server }),
          ...(descriptorFindings === undefined ? {} : { descriptorFindings }),
          ...(baselineFindings === undefined ? {} : { baselineFindings }),
          allowReview: options.allowReview === true
        });
        await writeJsonFile(paths.mcpGateJson, gate);

        const failOn = parseSeverityOption(options.failOn) ?? watchtowerConfig.policy.failOn;
        if (shouldFailForFindings(gate.admission.findings, failOn)) {
          throw new Error(summarizePolicyFailure(gate.admission.findings, failOn));
        }
        if (gate.launch.mode === "blocked") {
          throw new Error(`MCP proxy blocked launch: ${gate.launch.reason}`);
        }
        if (gate.server.transport !== "stdio" || gate.server.command === undefined) {
          throw new Error("proxy-mcp currently only supports configured stdio MCP servers.");
        }

        if (options.dryRun === true) {
          const state = createMcpProxyState({
            serverName: gate.server.name,
            ...(descriptorTools === undefined ? {} : { tools: descriptorTools }),
            ...(firewall === undefined ? {} : { firewall }),
            policy: watchtowerConfig.policy
          });
          await writeJsonFile(paths.mcpProxyAuditJson, createMcpProxyAuditReport(state));
          ctx.stdout(`Proxy dry-run ready for ${gate.server.name}.`);
          ctx.stdout(`Wrote ${paths.mcpProxyAuditJson}`);
          return;
        }

        ctx.stderr(`Starting MCP proxy for ${gate.server.name}. Audit: ${paths.mcpProxyAuditJson}`);
        await runStdioMcpProxy({
          cwd: ctx.cwd,
          server: gate.server,
          ...(descriptorTools === undefined ? {} : { tools: descriptorTools }),
          policy: watchtowerConfig.policy,
          ...(firewall === undefined ? {} : { firewall }),
          auditPath: paths.mcpProxyAuditJson
        });
      }
    );

  const firewall = program
    .command("firewall")
    .description("Generate and simulate local MCP Capability Firewall policy-as-code.");

  firewall
    .command("init")
    .option("-d, --descriptor <descriptor>", "MCP descriptor JSON to use when generating least-privilege rules.")
    .option("-o, --out <out>", "Firewall config output path. Defaults to .watchtower/firewall.json.")
    .description("Generate a starter Capability Firewall policy config.")
    .action(async (options: { descriptor?: string; out?: string }) => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const descriptorPath = options.descriptor === undefined ? bundledPath("examples", "mcp", "risky-tools.json") : resolve(ctx.cwd, options.descriptor);
      const descriptorScan = await scanMcpDescriptorFile(descriptorPath);
      const firewallConfig = createFirewallConfigFromTools(descriptorScan.tools, {
        description: `Least-privilege firewall policy generated from ${sourceUri(ctx.cwd, descriptorPath)}.`
      });
      const outPath = options.out === undefined ? paths.firewallConfigJson : resolve(ctx.cwd, options.out);
      await writeJsonFile(outPath, firewallConfig);
      ctx.stdout(`Firewall config written to ${outPath}`);
      ctx.stdout(`Rules: ${firewallConfig.rules.length}. Default: ${firewallConfig.defaultDecision}.`);
    });

  firewall
    .command("simulate")
    .requiredOption("-c, --config <config>", "Firewall policy config JSON.")
    .option("-t, --trace <trace>", "Trace file to replay through the firewall. Defaults to stored runs.")
    .option("--fail-on <severity>", "Exit non-zero when firewall findings meet this severity.")
    .description("Replay agent tool-call traces through a Capability Firewall policy.")
    .action(async (options: { config: string; trace?: string; failOn?: string }) => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const config = await loadWatchtowerConfig(ctx.cwd);
      const firewallConfig = await readFirewallConfigFile(resolve(ctx.cwd, options.config));
      const runs = await loadRunsForCommand(ctx.cwd, options.trace);
      const report = simulateFirewall(firewallConfig, runs);
      await writeJsonFile(paths.firewallReportJson, report);
      ctx.stdout(`Firewall simulation: ${report.summary.allowed} allowed, ${report.summary.denied} denied, ${report.summary.escalated} need approval.`);
      ctx.stdout(`Wrote ${paths.firewallReportJson}`);
      const failOn = parseSeverityOption(options.failOn) ?? config.policy.failOn;
      if (shouldFailForFindings(report.findings, failOn)) {
        throw new Error(summarizePolicyFailure(report.findings, failOn));
      }
    });

  program
    .command("protect-mcp")
    .requiredOption("-c, --config <config>", "MCP client JSON config to protect.")
    .requiredOption("-s, --server <server>", "MCP server name to wrap with the Watchtower proxy.")
    .option("-o, --out <out>", "Protected config output path. Defaults to .watchtower/protected/<config>.protected.json.")
    .option("--in-place", "Modify the original config after writing a backup and rollback manifest.")
    .option("-d, --descriptor <descriptor>", "MCP descriptor JSON to pass through to proxy-mcp.")
    .option("-b, --baseline <baseline>", "Watchtower MCP baseline file to pass through to proxy-mcp.")
    .option("--firewall <firewall>", "Capability Firewall policy config to pass through to proxy-mcp.")
    .option("--fail-on <severity>", "Proxy policy threshold to pass through to proxy-mcp.")
    .option("--package <packageSpec>", "npm package spec used in the protected npx wrapper.")
    .description("Create a protected MCP client config that routes one server through the Watchtower proxy.")
    .action(
      async (options: ProtectMcpCommandOptions) => {
        const result = await runMcpProtection(ctx, options);
        if (result.backupConfigPath !== undefined) {
          ctx.stdout(`Backup written to ${result.backupConfigPath}`);
        }
        ctx.stdout(`Protected config written to ${result.protectedConfigPath}`);
        ctx.stdout(`Protection manifest written to ${result.manifestPath}`);
      }
    );

  program
    .command("unprotect-mcp")
    .requiredOption("-c, --config <config>", "Protected MCP client JSON config to restore.")
    .option("--manifest <manifest>", "Protection manifest path. Defaults to .watchtower/protected/<config>.protection.json.")
    .description("Restore an MCP server from a Watchtower protection manifest.")
    .action(async (options: { config: string; manifest?: string }) => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const configPath = resolve(ctx.cwd, options.config);
      const protectionPaths = getMcpProtectionPaths(ctx.cwd, paths, configPath, undefined, true);
      const manifestPath = options.manifest === undefined ? protectionPaths.manifestPath : resolve(ctx.cwd, options.manifest);
      const config = JSON.parse(await readFile(configPath, "utf8")) as unknown;
      const manifest = parseMcpProtectionManifest(JSON.parse(await readFile(manifestPath, "utf8")) as unknown);
      const restored = restoreMcpProtection(config, manifest);
      await writeJsonFile(configPath, restored);
      ctx.stdout(`Restored MCP config ${configPath}`);
    });

  program
    .command("agent-bom")
    .requiredOption("-c, --config <config...>", "MCP client config file(s) to include in the Agent Bill of Materials.")
    .option("-d, --descriptor <descriptor>", "MCP descriptor JSON to include as tool inventory.")
    .option("--cyclonedx", "Also write a CycloneDX-compatible AgentBOM export.")
    .option("--fail-on <severity>", "Exit non-zero when AgentBOM findings meet this severity.")
    .description("Generate a local Agent Bill of Materials for MCP servers, tools, config sources, and findings.")
    .action(async (options: { config: string[]; descriptor?: string; cyclonedx?: boolean; failOn?: string }) => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const watchtowerConfig = await loadWatchtowerConfig(ctx.cwd);
      const inventory = await inventoryMcpConfigFiles(
        explicitMcpConfigCandidates(options.config.map((configPath) => resolve(ctx.cwd, configPath)))
      );
      await writeJsonFile(paths.mcpInventoryJson, inventory);

      const descriptorScan =
        options.descriptor === undefined
          ? undefined
          : await scanMcpDescriptorFile(resolve(ctx.cwd, options.descriptor), watchtowerConfig.policy);
      if (descriptorScan !== undefined) {
        await writeJsonFile(join(paths.reportsDir, "mcp-scan.json"), descriptorScan);
      }

      const bom = createAgentBom({
        inventory,
        ...(descriptorScan === undefined ? {} : { tools: descriptorScan.tools, findings: descriptorScan.findings })
      });
      await writeJsonFile(paths.agentBomJson, bom);
      await writeFile(paths.agentBomMarkdown, renderAgentBomMarkdown(bom), "utf8");
      if (options.cyclonedx === true) {
        await writeJsonFile(paths.agentBomCycloneDxJson, exportCycloneDxAgentBom(bom));
        ctx.stdout(`Wrote ${paths.agentBomCycloneDxJson}`);
      }
      ctx.stdout(`Wrote ${paths.agentBomJson}`);
      ctx.stdout(`Wrote ${paths.agentBomMarkdown}`);
      ctx.stdout(`AgentBOM inventory: ${bom.summary.mcpServers} servers, ${bom.summary.mcpTools} tools, ${bom.summary.findings} findings.`);

      const failOn = parseSeverityOption(options.failOn) ?? watchtowerConfig.policy.failOn;
      if (shouldFailForFindings(bom.findings, failOn)) {
        throw new Error(summarizePolicyFailure(bom.findings, failOn));
      }
    });

  program
    .command("attest-mcp")
    .option("--subject <subject>", "Human-readable subject for the evidence bundle.")
    .option("--private-key <privateKey>", "PEM Ed25519 private key path for signing the evidence bundle.")
    .option("--key-id <keyId>", "Stable signing key id to embed in the evidence bundle signature.")
    .description("Create a tamper-evident evidence bundle from Watchtower MCP reports.")
    .action(async (options: { subject?: string; privateKey?: string; keyId?: string }) => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const artifacts = await existingEvidenceArtifacts(paths);
      if (artifacts.length === 0) {
        throw new Error("No Watchtower MCP report artifacts found. Run admit-mcp, scan-mcp, inventory-mcp, diff-mcp, or firewall simulate first.");
      }
      const admissionDecision = await readAdmissionDecision(paths.mcpAdmissionJson);
      const bundle = await createEvidenceBundle({
        cwd: ctx.cwd,
        ...(options.subject === undefined ? {} : { subject: options.subject }),
        ...(admissionDecision === undefined ? {} : { admissionDecision }),
        artifacts
      });
      const signedBundle =
        options.privateKey === undefined
          ? bundle
          : signEvidenceBundle(bundle, {
              privateKeyPem: await readFile(resolve(ctx.cwd, options.privateKey), "utf8"),
              keyId: options.keyId ?? "local"
            });
      await writeJsonFile(paths.evidenceBundleJson, signedBundle);
      ctx.stdout(`Wrote evidence bundle to ${paths.evidenceBundleJson}`);
      ctx.stdout(`Integrity hash: ${signedBundle.integrityHash}`);
      if (signedBundle.signature !== undefined) {
        ctx.stdout(`Signature: ${signedBundle.signature.algorithm} key ${signedBundle.signature.keyId}`);
      }
    });

  program
    .command("verify-attestation")
    .argument("[bundle]", "Evidence bundle path. Defaults to .watchtower/reports/evidence-bundle.json.")
    .option("--public-key <publicKey>", "PEM Ed25519 public key path for verifying a signed evidence bundle.")
    .description("Verify a Watchtower evidence bundle against current local artifacts.")
    .action(async (bundle: string | undefined, options: { publicKey?: string }) => {
      const paths = getWatchtowerPaths(ctx.cwd);
      const bundlePath = bundle === undefined ? paths.evidenceBundleJson : resolve(ctx.cwd, bundle);
      const evidence = JSON.parse(await readFile(bundlePath, "utf8")) as Awaited<ReturnType<typeof createEvidenceBundle>>;
      const verification = await verifyEvidenceBundle(evidence, ctx.cwd, {
        ...(options.publicKey === undefined ? {} : { publicKeyPem: await readFile(resolve(ctx.cwd, options.publicKey), "utf8") })
      });
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
    .command("analyze-run")
    .option("-t, --trace <trace>", "Analyze this trace instead of stored runs.")
    .option("-m, --mcp <descriptor>", "MCP descriptor JSON to use as runtime classification context.")
    .option("-c, --config <config...>", "MCP client config file(s) to use as runtime classification context.")
    .option("--fail-on <severity>", "Exit non-zero when runtime attack graph findings meet this severity.")
    .option("--sarif", "Also write GitHub code scanning SARIF output.")
    .description("Build a deterministic runtime attack graph from agent tool-call traces.")
    .action(
      async (options: { trace?: string; mcp?: string; config?: string[]; failOn?: string; sarif?: boolean }) => {
        const paths = await ensureWatchtowerDirs(ctx.cwd);
        const watchtowerConfig = await loadWatchtowerConfig(ctx.cwd);
        const runs = await loadRunsForCommand(ctx.cwd, options.trace);
        const graphContext = await loadAttackGraphContext(ctx.cwd, paths, options.mcp, options.config, watchtowerConfig.policy);
        const graph = analyzeRuns(runs, graphContext);
        await writeJsonFile(paths.attackGraphJson, graph);
        if (options.sarif === true) {
          await writeJsonFile(
            paths.sarifJson,
            exportSarif(graph.findings, {
              ...(options.trace === undefined ? {} : { sourceUri: sourceUri(ctx.cwd, resolve(ctx.cwd, options.trace)) }),
              invocationCommandLine: "agentops-watchtower analyze-run --sarif"
            })
          );
          ctx.stdout(`Wrote ${paths.sarifJson}`);
        }
        ctx.stdout(`Analyzed ${graph.summary.toolCalls} tool calls. Runtime findings: ${graph.summary.findings}.`);
        ctx.stdout(`Wrote ${paths.attackGraphJson}`);
        const failOn = parseSeverityOption(options.failOn) ?? watchtowerConfig.policy.failOn;
        if (shouldFailForFindings(graph.findings, failOn)) {
          throw new Error(summarizePolicyFailure(graph.findings, failOn));
        }
      }
    );

  program
    .command("report")
    .option("-t, --trace <trace>", "Import this trace before generating the report.")
    .option("-m, --mcp <descriptor>", "Scan this MCP descriptor and include findings.")
    .option("--analyze", "Include runtime attack graph findings from local runs or the provided trace.")
    .option("--fail-on <severity>", "Exit non-zero when report findings meet this severity.")
    .description("Generate Markdown, HTML, and JSON reports from local runs and optional MCP scan findings.")
    .action(async (options: { trace?: string; mcp?: string; analyze?: boolean; failOn?: string }) => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      const config = await loadWatchtowerConfig(ctx.cwd);
      const runs = await loadRunsForCommand(ctx.cwd, options.trace);
      const mcpFindings = await loadMcpFindings(ctx.cwd, options.mcp, config.policy);
      const attackGraph =
        options.analyze === true
          ? analyzeRuns(runs, await loadAttackGraphContext(ctx.cwd, paths, options.mcp, undefined, config.policy))
          : undefined;
      if (attackGraph !== undefined) {
        await writeJsonFile(paths.attackGraphJson, attackGraph);
      }
      const evalResults = evaluateRuns(runs);
      const report = createWatchtowerReport({
        runs,
        findings: [...runs.flatMap((run) => run.findings), ...mcpFindings, ...(attackGraph?.findings ?? [])],
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
      const attackTracePath = bundledPath("examples", "traces", "source-to-sink.jsonl");
      const mcpPath = bundledPath("examples", "mcp", "risky-tools.json");
      const safeMcpPath = bundledPath("examples", "mcp", "safe-tools.json");
      const run = await importTraceFile(tracePath);
      const attackRun = await importTraceFile(attackTracePath);
      const mcpScan = await scanMcpDescriptorFile(mcpPath);
      const safeMcpScan = await scanMcpDescriptorFile(safeMcpPath);
      const attackGraph = analyzeRuns([attackRun]);
      const demoRuns = [run, attackRun];
      const firewallConfig = createFirewallConfigFromTools(mcpScan.tools, {
        description: "Demo least-privilege policy generated from examples/mcp/risky-tools.json."
      });
      const firewallReport = simulateFirewall(firewallConfig, demoRuns);
      const evalResults = evaluateRuns(demoRuns);
      const report = createWatchtowerReport({
        runs: demoRuns,
        findings: [
          ...demoRuns.flatMap((demoRun) => demoRun.findings),
          ...mcpScan.findings,
          ...attackGraph.findings,
          ...firewallReport.findings
        ],
        evalResults
      });

      await appendRunJsonl(paths.runsJsonl, run);
      await appendRunJsonl(paths.runsJsonl, attackRun);
      await writeJsonFile(join(paths.runsDir, `${run.id}.json`), run);
      await writeJsonFile(join(paths.runsDir, `${attackRun.id}.json`), attackRun);
      await writeJsonFile(join(paths.reportsDir, "mcp-scan.json"), mcpScan);
      await writeJsonFile(paths.attackGraphJson, attackGraph);
      await writeJsonFile(paths.firewallConfigJson, firewallConfig);
      await writeJsonFile(paths.firewallReportJson, firewallReport);
      await writeJsonFile(paths.mcpBaselineJson, createMcpBaseline(safeMcpScan.tools, { source: "examples/mcp/safe-tools.json" }));
      await writeJsonFile(paths.sarifJson, exportSarif(mcpScan.findings, { sourceUri: "examples/mcp/risky-tools.json" }));
      await writeReportFiles(paths, report, renderMarkdownReport(report), renderHtmlReport(report));
      ctx.stdout(`Demo complete. Risk score: ${report.summary.riskScore}.`);
      ctx.stdout(`Open ${paths.reportMarkdown} or ${paths.reportHtml}.`);
    });

  program
    .command("evidence")
    .description("Write normalized Agent Trust Center evidence from the latest Watchtower report.")
    .action(async () => {
      const paths = await ensureWatchtowerDirs(ctx.cwd);
      if (!(await fileExists(paths.reportJson))) {
        throw new Error("No Watchtower report found. Run agentops-watchtower demo or report first.");
      }
      const evidence = await createWatchtowerTrustEvidence({
        paths,
        version: readPackageVersion()
      });
      const outputPath = trustEvidencePath(paths);
      await writeJsonFile(outputPath, evidence);
      ctx.stdout(`Decision: ${evidence.decision.toUpperCase()}`);
      ctx.stdout(`Trust evidence: ${outputPath}`);
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

interface SetupCommandResult {
  paths: ReturnType<typeof getWatchtowerPaths>;
  configCreated: boolean;
  slashCommandsWritten: number;
}

interface CombinedCheckOptions {
  descriptor?: string;
  mcp?: string;
  config?: string[];
  trace?: string;
  firewall?: string;
  sarif?: boolean;
  failOn?: string;
}

interface CombinedCheckResult {
  paths: ReturnType<typeof getWatchtowerPaths>;
  report: ReturnType<typeof createWatchtowerReport>;
  artifacts: string[];
}

function createDefaultWatchtowerConfig(): LocalWatchtowerConfigFile {
  return {
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
  };
}

async function initializeWatchtower(cwd: string): Promise<InitializeWatchtowerResult> {
  const paths = await ensureWatchtowerDirs(cwd);
  if (await fileExists(paths.config)) {
    return { paths, created: false };
  }
  await writeJsonFile(paths.config, createDefaultWatchtowerConfig());
  return { paths, created: true };
}

async function runSetup(ctx: CliContext, options: { descriptor?: string; skipSlashCommands?: boolean }): Promise<SetupCommandResult> {
  const initialized = await initializeWatchtower(ctx.cwd);
  const config = await loadWatchtowerConfig(ctx.cwd);
  const descriptorPath = options.descriptor === undefined ? bundledPath("examples", "mcp", "risky-tools.json") : resolve(ctx.cwd, options.descriptor);
  const descriptorScan = await scanMcpDescriptorFile(descriptorPath, config.policy);
  const firewallConfig = createFirewallConfigFromTools(descriptorScan.tools, {
    description: `Least-privilege firewall policy generated from ${sourceUri(ctx.cwd, descriptorPath)}.`
  });
  await writeJsonFile(join(initialized.paths.reportsDir, "mcp-scan.json"), descriptorScan);
  await writeJsonFile(initialized.paths.firewallConfigJson, firewallConfig);
  const slashCommandsWritten = options.skipSlashCommands === true ? 0 : await writeSlashCommandTemplates(initialized.paths);
  return {
    paths: initialized.paths,
    configCreated: initialized.created,
    slashCommandsWritten
  };
}

async function runCombinedCheck(ctx: CliContext, options: CombinedCheckOptions): Promise<CombinedCheckResult> {
  const paths = await ensureWatchtowerDirs(ctx.cwd);
  const config = await loadWatchtowerConfig(ctx.cwd);
  const runs = await loadRunsForCommand(ctx.cwd, options.trace);
  const artifacts: string[] = [];
  const descriptor = options.descriptor ?? options.mcp;
  const descriptorPath = descriptor === undefined ? undefined : resolve(ctx.cwd, descriptor);
  let descriptorScan: Awaited<ReturnType<typeof scanMcpDescriptorFile>> | undefined;
  let inventory: Awaited<ReturnType<typeof inventoryMcpConfigFiles>> | undefined;
  let mcpFindings: RiskFinding[] = [];
  let inventoryFindings: RiskFinding[] = [];
  let firewallFindings: RiskFinding[] = [];

  if (descriptorPath !== undefined) {
    descriptorScan = await scanMcpDescriptorFile(descriptorPath, config.policy);
    await writeJsonFile(join(paths.reportsDir, "mcp-scan.json"), descriptorScan);
    mcpFindings = descriptorScan.findings;
    artifacts.push(join(paths.reportsDir, "mcp-scan.json"));
  }

  if (options.config !== undefined && options.config.length > 0) {
    inventory = await inventoryMcpConfigFiles(
      explicitMcpConfigCandidates(options.config.map((configPath) => resolve(ctx.cwd, configPath)))
    );
    await writeJsonFile(paths.mcpInventoryJson, inventory);
    inventoryFindings = inventory.findings;
    artifacts.push(paths.mcpInventoryJson);
  }

  const graph = analyzeRuns(runs, {
    ...(descriptorScan === undefined ? {} : { tools: descriptorScan.tools }),
    ...(inventory === undefined ? {} : { inventory })
  });
  await writeJsonFile(paths.attackGraphJson, graph);
  artifacts.push(paths.attackGraphJson);

  if (options.firewall !== undefined) {
    const firewallConfig = await readFirewallConfigFile(resolve(ctx.cwd, options.firewall));
    const firewallReport = simulateFirewall(firewallConfig, runs);
    await writeJsonFile(paths.firewallReportJson, firewallReport);
    firewallFindings = firewallReport.findings;
    artifacts.push(paths.firewallReportJson);
  }

  const evalResults = evaluateRuns(runs);
  const report = createWatchtowerReport({
    runs,
    findings: [
      ...runs.flatMap((run) => run.findings),
      ...mcpFindings,
      ...inventoryFindings,
      ...graph.findings,
      ...firewallFindings
    ],
    evalResults
  });
  await writeReportFiles(paths, report, renderMarkdownReport(report), renderHtmlReport(report));
  artifacts.push(paths.reportJson, paths.reportMarkdown, paths.reportHtml);

  if (options.sarif === true) {
    const tracePath = options.trace === undefined ? undefined : resolve(ctx.cwd, options.trace);
    await writeJsonFile(
      paths.sarifJson,
      exportSarif(report.findings, {
        ...(descriptorPath === undefined && tracePath === undefined
          ? {}
          : { sourceUri: sourceUri(ctx.cwd, descriptorPath ?? tracePath ?? ctx.cwd) }),
        invocationCommandLine: "agentops-watchtower check --sarif"
      })
    );
    artifacts.push(paths.sarifJson);
  }

  const failOn = parseSeverityOption(options.failOn) ?? config.policy.failOn;
  if (shouldFailForFindings(report.findings, failOn)) {
    throw new Error(summarizePolicyFailure(report.findings, failOn));
  }

  return { paths, report, artifacts };
}

async function runMcpProtection(ctx: CliContext, options: ProtectMcpCommandOptions): Promise<ProtectMcpCommandResult> {
  const paths = await ensureWatchtowerDirs(ctx.cwd);
  const configPath = resolve(ctx.cwd, options.config);
  if (extname(configPath).toLowerCase() !== ".json") {
    throw new Error("protect-mcp currently supports JSON MCP configs.");
  }
  const rawConfig = JSON.parse(await readFile(configPath, "utf8")) as unknown;
  const protectionPaths = getMcpProtectionPaths(ctx.cwd, paths, configPath, options.out, options.inPlace === true);
  const packageSpec = options.package ?? `agentops-watchtower@${readPackageVersion()}`;
  const failOn = parseSeverityOption(options.failOn);
  const descriptorPath = options.descriptor === undefined ? undefined : resolve(ctx.cwd, options.descriptor);
  const baselinePath = options.baseline === undefined ? undefined : resolve(ctx.cwd, options.baseline);
  const firewallPath = options.firewall === undefined ? undefined : resolve(ctx.cwd, options.firewall);
  const protection = createMcpProtection(rawConfig, {
    serverName: options.server,
    originalConfigPath: configPath,
    protectedConfigPath: protectionPaths.protectedConfigPath,
    ...(protectionPaths.backupConfigPath === undefined ? {} : { backupConfigPath: protectionPaths.backupConfigPath }),
    packageSpec,
    ...(descriptorPath === undefined ? {} : { descriptorPath }),
    ...(baselinePath === undefined ? {} : { baselinePath }),
    ...(firewallPath === undefined ? {} : { firewallPath }),
    ...(failOn === undefined ? {} : { failOn })
  });

  if (protectionPaths.backupConfigPath !== undefined) {
    await writeJsonFile(protectionPaths.backupConfigPath, rawConfig);
  }
  await mkdir(dirname(protectionPaths.protectedConfigPath), { recursive: true });
  await writeJsonFile(protectionPaths.protectedConfigPath, protection.protectedConfig);
  await writeJsonFile(protectionPaths.manifestPath, protection.manifest);

  const result: ProtectMcpCommandResult = {
    protectedConfigPath: protectionPaths.protectedConfigPath,
    manifestPath: protectionPaths.manifestPath
  };
  if (protectionPaths.backupConfigPath !== undefined) {
    result.backupConfigPath = protectionPaths.backupConfigPath;
  }
  return result;
}

async function writeSlashCommandTemplates(paths: ReturnType<typeof getWatchtowerPaths>): Promise<number> {
  const templates = createSlashCommandTemplates();
  await mkdir(paths.slashCommandsDir, { recursive: true });
  await Promise.all(
    templates.map((template) => writeFile(join(paths.slashCommandsDir, template.filename), template.content, "utf8"))
  );
  return templates.length;
}

function createSlashCommandTemplates(): Array<{ filename: string; content: string }> {
  return [
    {
      filename: "watchtower-check.md",
      content: [
        "# /watchtower-check",
        "",
        "Run a local AgentOps Watchtower assessment without sending data to a cloud service.",
        "",
        "Suggested command:",
        "",
        "```bash",
        "npx agentops-watchtower check --descriptor <mcp-tools.json> --trace <trace.jsonl> --firewall .watchtower/firewall.json",
        "```",
        "",
        "Keep the advanced commands available when deeper control is needed: scan-mcp, inventory-mcp, analyze-run, firewall simulate, report, and attest-mcp.",
        ""
      ].join("\n")
    },
    {
      filename: "watchtower-protect.md",
      content: [
        "# /watchtower-protect",
        "",
        "Protect one configured stdio MCP server by routing it through the Watchtower proxy and optional Capability Firewall.",
        "",
        "Suggested command:",
        "",
        "```bash",
        "npx agentops-watchtower protect --config <mcp-client.json> --server <server-name> --firewall .watchtower/firewall.json",
        "```",
        "",
        "Use protect-mcp directly when you need the full advanced flag surface.",
        ""
      ].join("\n")
    },
    {
      filename: "watchtower-report.md",
      content: [
        "# /watchtower-report",
        "",
        "Generate human-readable and machine-readable evidence for the latest local agent run.",
        "",
        "Suggested command:",
        "",
        "```bash",
        "npx agentops-watchtower report --analyze",
        "```",
        "",
        "For CI or audit evidence, follow with: npx agentops-watchtower attest-mcp.",
        ""
      ].join("\n")
    }
  ];
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
      checks.push({ name: "config", ok, message: ok ? "config.json is valid enough for v0.7" : "config.json is malformed" });
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

async function loadAttackGraphContext(
  cwd: string,
  paths: ReturnType<typeof getWatchtowerPaths>,
  descriptor: string | undefined,
  configs: string[] | undefined,
  options: McpScanOptions
): Promise<AttackGraphContext> {
  const descriptorScan =
    descriptor === undefined ? undefined : await scanMcpDescriptorFile(resolve(cwd, descriptor), options);
  if (descriptorScan !== undefined) {
    await writeJsonFile(join(paths.reportsDir, "mcp-scan.json"), descriptorScan);
  }

  const inventory =
    configs === undefined || configs.length === 0
      ? undefined
      : await inventoryMcpConfigFiles(explicitMcpConfigCandidates(configs.map((configPath) => resolve(cwd, configPath))));
  if (inventory !== undefined) {
    await writeJsonFile(paths.mcpInventoryJson, inventory);
  }

  return {
    ...(descriptorScan === undefined ? {} : { tools: descriptorScan.tools }),
    ...(inventory === undefined ? {} : { inventory })
  };
}

function bundledPath(...segments: string[]): string {
  return join(packageRoot, ...segments);
}

function sourceUri(cwd: string, path: string): string {
  const relativePath = relative(cwd, path);
  return (relativePath.startsWith("..") ? path : relativePath).replaceAll("\\", "/");
}

interface McpProtectionFilePaths {
  protectedConfigPath: string;
  manifestPath: string;
  backupConfigPath?: string;
}

function getMcpProtectionPaths(
  cwd: string,
  paths: ReturnType<typeof getWatchtowerPaths>,
  configPath: string,
  out: string | undefined,
  inPlace: boolean
): McpProtectionFilePaths {
  const extension = extname(configPath);
  const outputExtension = extension.length === 0 ? ".json" : extension;
  const stem = basename(configPath, extension);
  const protectedConfigPath = inPlace
    ? configPath
    : resolve(cwd, out ?? join(paths.protectedDir, `${stem}.protected${outputExtension}`));
  const manifestPath = join(paths.protectedDir, `${stem}.protection.json`);
  if (!inPlace) {
    return { protectedConfigPath, manifestPath };
  }
  return {
    protectedConfigPath,
    manifestPath,
    backupConfigPath: join(paths.protectedDir, `${stem}.backup${outputExtension}`)
  };
}

function parseMcpProtectionManifest(value: unknown): McpProtectionManifest {
  if (!isPlainRecord(value)) {
    throw new Error("Invalid MCP protection manifest: expected a JSON object.");
  }
  if (value["schemaVersion"] !== 1) {
    throw new Error("Invalid MCP protection manifest: schemaVersion must be 1.");
  }
  const mode = value["mode"];
  if (mode !== "copy" && mode !== "in-place") {
    throw new Error("Invalid MCP protection manifest: mode must be copy or in-place.");
  }
  const originalServer = value["originalServer"];
  const protectedServer = value["protectedServer"];
  if (!isPlainRecord(originalServer) || !isPlainRecord(protectedServer)) {
    throw new Error("Invalid MCP protection manifest: server entries must be JSON objects.");
  }

  const manifest: McpProtectionManifest = {
    schemaVersion: 1,
    protectedAt: requireStringField(value, "protectedAt"),
    mode,
    serverName: requireStringField(value, "serverName"),
    originalConfigPath: requireStringField(value, "originalConfigPath"),
    protectedConfigPath: requireStringField(value, "protectedConfigPath"),
    packageSpec: requireStringField(value, "packageSpec"),
    originalServer,
    protectedServer
  };
  const backupConfigPath = optionalStringField(value, "backupConfigPath");
  const descriptorPath = optionalStringField(value, "descriptorPath");
  const baselinePath = optionalStringField(value, "baselinePath");
  const firewallPath = optionalStringField(value, "firewallPath");
  const failOn = optionalStringField(value, "failOn");
  if (backupConfigPath !== undefined) {
    manifest.backupConfigPath = backupConfigPath;
  }
  if (descriptorPath !== undefined) {
    manifest.descriptorPath = descriptorPath;
  }
  if (baselinePath !== undefined) {
    manifest.baselinePath = baselinePath;
  }
  if (firewallPath !== undefined) {
    manifest.firewallPath = firewallPath;
  }
  if (failOn !== undefined) {
    manifest.failOn = failOn;
  }
  return manifest;
}

function requireStringField(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Invalid MCP protection manifest: ${field} must be a string.`);
  }
  return value;
}

function optionalStringField(record: Record<string, unknown>, field: string): string | undefined {
  const value = record[field];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Invalid MCP protection manifest: ${field} must be a string when present.`);
  }
  return value;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

async function existingEvidenceArtifacts(paths: ReturnType<typeof getWatchtowerPaths>): Promise<EvidenceArtifactInput[]> {
  const candidates: EvidenceArtifactInput[] = [
    { name: "mcp-admission", path: paths.mcpAdmissionJson },
    { name: "mcp-inventory", path: paths.mcpInventoryJson },
    { name: "mcp-scan", path: join(paths.reportsDir, "mcp-scan.json") },
    { name: "mcp-baseline-diff", path: paths.mcpBaselineDiffJson },
    { name: "mcp-gate", path: paths.mcpGateJson },
    { name: "mcp-proxy-audit", path: paths.mcpProxyAuditJson },
    { name: "firewall-report", path: paths.firewallReportJson },
    { name: "agent-bom", path: paths.agentBomJson },
    { name: "agent-bom-markdown", path: paths.agentBomMarkdown },
    { name: "agent-bom-cyclonedx", path: paths.agentBomCycloneDxJson },
    { name: "attack-graph", path: paths.attackGraphJson },
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
