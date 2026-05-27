import { access, readFile } from "node:fs/promises";
import { join } from "node:path";
import { createFinding } from "./risk.js";
import { isSensitiveKey } from "./redaction.js";
import type { RiskFinding } from "./schemas.js";

export type McpConfigClient = "codex" | "claude-code" | "claude-desktop" | "cursor" | "vscode" | "gemini" | "unknown";
export type McpConfigScope = "project" | "user" | "profile" | "explicit" | "unknown";
export type McpConfigFormat = "json" | "toml";
export type McpServerTransport = "stdio" | "http" | "sse" | "unknown";

export interface McpConfigCandidate {
  path: string;
  client: McpConfigClient;
  scope: McpConfigScope;
}

export interface McpInventorySource extends McpConfigCandidate {
  format: McpConfigFormat;
  status: "parsed" | "missing";
}

export interface ConfiguredMcpServer {
  id: string;
  name: string;
  client: McpConfigClient;
  sourcePath: string;
  scope: McpConfigScope;
  transport: McpServerTransport;
  command?: string;
  args: string[];
  url?: string;
  envKeys: string[];
}

export interface McpInventory {
  generatedAt: string;
  sources: McpInventorySource[];
  servers: ConfiguredMcpServer[];
  findings: RiskFinding[];
}

interface DiscoveryOptions {
  cwd: string;
  home?: string;
  appData?: string;
}

interface RawServer {
  name: string;
  command?: string;
  args: string[];
  url?: string;
  type?: string;
  env: Record<string, string>;
  headers: Record<string, string>;
  trust?: boolean;
}

const DANGEROUS_SHELL_PATTERN = /\b(curl|wget|irm|iwr|invoke-webrequest)\b.+\|\s*(sh|bash|iex|invoke-expression)\b|\brm\s+-rf\b|\bdel\s+\/[sq]\b|\bformat\s+[a-z]:|\binvoke-expression\b|\biex\b/i;
const SHELL_COMMANDS = new Set(["bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"]);
const PACKAGE_RUNNERS = new Set(["npx", "npx.cmd", "npx.exe", "uvx", "uvx.exe"]);

export function discoverMcpConfigCandidates(options: DiscoveryOptions): McpConfigCandidate[] {
  const candidates: McpConfigCandidate[] = [
    { path: join(options.cwd, ".mcp.json"), client: "claude-code", scope: "project" },
    { path: join(options.cwd, ".cursor", "mcp.json"), client: "cursor", scope: "project" },
    { path: join(options.cwd, ".vscode", "mcp.json"), client: "vscode", scope: "project" },
    { path: join(options.cwd, ".gemini", "settings.json"), client: "gemini", scope: "project" },
    { path: join(options.cwd, ".codex", "config.toml"), client: "codex", scope: "project" }
  ];

  if (options.home !== undefined) {
    candidates.push(
      { path: join(options.home, ".codex", "config.toml"), client: "codex", scope: "user" },
      { path: join(options.home, ".claude.json"), client: "claude-code", scope: "user" },
      { path: join(options.home, ".cursor", "mcp.json"), client: "cursor", scope: "user" },
      { path: join(options.home, ".gemini", "settings.json"), client: "gemini", scope: "user" }
    );
  }

  if (options.appData !== undefined) {
    candidates.push(
      { path: join(options.appData, "Claude", "claude_desktop_config.json"), client: "claude-desktop", scope: "profile" },
      { path: join(options.appData, "Code", "User", "mcp.json"), client: "vscode", scope: "user" }
    );
  }

  return candidates;
}

export async function inventoryMcpConfigFiles(candidates: readonly McpConfigCandidate[]): Promise<McpInventory> {
  const sources: McpInventorySource[] = [];
  const servers: ConfiguredMcpServer[] = [];
  const findings: RiskFinding[] = [];

  for (const candidate of candidates) {
    const format = detectFormat(candidate.path);
    if (!(await fileExists(candidate.path))) {
      sources.push({ ...candidate, format, status: "missing" });
      continue;
    }

    const rawServers = await parseMcpConfigFile(candidate.path, format);
    sources.push({ ...candidate, format, status: "parsed" });
    for (const rawServer of rawServers) {
      const server = normalizeServer(rawServer, candidate);
      servers.push(server);
      findings.push(...scanServerConfig(server, rawServer));
    }
  }

  return {
    generatedAt: new Date().toISOString(),
    sources,
    servers: servers.sort(compareServers),
    findings: findings.sort((left, right) => left.id.localeCompare(right.id))
  };
}

export function explicitMcpConfigCandidates(paths: readonly string[]): McpConfigCandidate[] {
  return paths.map((path) => ({
    path,
    client: inferClientFromPath(path),
    scope: "explicit"
  }));
}

async function parseMcpConfigFile(path: string, format: McpConfigFormat): Promise<RawServer[]> {
  const content = await readFile(path, "utf8");

  if (format === "toml") {
    return parseCodexToml(content);
  }

  try {
    return parseJsonConfig(JSON.parse(content) as unknown);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown parse error";
    throw new Error(`Could not parse MCP config JSON at ${path}: ${message}`);
  }
}

function parseJsonConfig(value: unknown): RawServer[] {
  const serverMaps = collectServerMaps(value);
  return serverMaps.flatMap((serverMap) =>
    Object.entries(serverMap).map(([name, server]) => parseRawServer(name, isRecord(server) ? server : {}))
  );
}

function collectServerMaps(value: unknown): Array<Record<string, unknown>> {
  if (!isRecord(value)) {
    return [];
  }

  const maps: Array<Record<string, unknown>> = [];
  const mcpServers = value["mcpServers"];
  const servers = value["servers"];
  if (isRecord(mcpServers)) {
    maps.push(mcpServers);
  }
  if (isRecord(servers)) {
    maps.push(servers);
  }

  for (const child of Object.values(value)) {
    if (isRecord(child) || Array.isArray(child)) {
      maps.push(...collectServerMaps(child));
    }
  }

  return maps;
}

function parseCodexToml(content: string): RawServer[] {
  const servers = new Map<string, Record<string, unknown>>();
  let currentName: string | undefined;

  for (const rawLine of content.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#")) {
      continue;
    }

    const section = /^\[mcp_servers\.([A-Za-z0-9_.-]+)\]$/u.exec(line);
    if (section !== null) {
      const sectionName = section[1];
      if (sectionName === undefined) {
        continue;
      }
      currentName = sectionName;
      servers.set(currentName, {});
      continue;
    }

    if (currentName === undefined) {
      continue;
    }

    const assignment = /^([A-Za-z0-9_.-]+)\s*=\s*(.+)$/u.exec(line);
    if (assignment === null) {
      continue;
    }

    const [, key, value] = assignment;
    if (key === undefined || value === undefined) {
      continue;
    }

    const server = servers.get(currentName);
    if (server === undefined) {
      continue;
    }

    if (key.startsWith("env.")) {
      const env = isRecord(server["env"]) ? server["env"] : {};
      env[key.slice("env.".length)] = parseTomlValue(value);
      server["env"] = env;
    } else {
      server[key] = parseTomlValue(value);
    }
  }

  return [...servers.entries()].map(([name, server]) => parseRawServer(name, server));
}

function parseRawServer(name: string, server: Record<string, unknown>): RawServer {
  const command = stringValue(server["command"]);
  const url = stringValue(server["url"]) ?? stringValue(server["httpUrl"]);
  const type = stringValue(server["type"]);
  const trust = typeof server["trust"] === "boolean" ? server["trust"] : undefined;

  return {
    name,
    ...(command === undefined ? {} : { command }),
    args: stringArray(server["args"]),
    ...(url === undefined ? {} : { url }),
    ...(type === undefined ? {} : { type }),
    env: stringRecord(server["env"]),
    headers: stringRecord(server["headers"]),
    ...(trust === undefined ? {} : { trust })
  };
}

function normalizeServer(server: RawServer, source: McpConfigCandidate): ConfiguredMcpServer {
  return {
    id: `${source.client}:${source.scope}:${server.name}`,
    name: server.name,
    client: source.client,
    sourcePath: source.path,
    scope: source.scope,
    transport: inferTransport(server),
    ...(server.command === undefined ? {} : { command: server.command }),
    args: server.args,
    ...(server.url === undefined ? {} : { url: server.url }),
    envKeys: Object.keys(server.env).sort()
  };
}

function scanServerConfig(server: ConfiguredMcpServer, rawServer: RawServer): RiskFinding[] {
  const findings: RiskFinding[] = [];
  const commandText = `${server.command ?? ""} ${server.args.join(" ")}`.trim();

  if (DANGEROUS_SHELL_PATTERN.test(commandText)) {
    findings.push(
      createFinding({
        idSeed: `${server.id}-dangerous-shell`,
        severity: "critical",
        category: "mcp.config.dangerous_shell",
        title: `${server.name} runs a dangerous shell command`,
        description: "The MCP server configuration includes shell install or destructive command patterns.",
        recommendation: "Replace shell pipelines and destructive commands with a reviewed executable or pinned package.",
        target: server.name,
        evidence: [commandText]
      })
    );
  } else if (server.command !== undefined && SHELL_COMMANDS.has(commandName(server.command))) {
    findings.push(
      createFinding({
        idSeed: `${server.id}-shell-execution`,
        severity: "high",
        category: "mcp.config.shell_execution",
        title: `${server.name} starts through a shell`,
        description: "Shell-based MCP launchers can hide command injection, downloads, and platform-specific behavior.",
        recommendation: "Launch the MCP server executable directly instead of through a shell.",
        target: server.name,
        evidence: [commandText]
      })
    );
  }

  const packageName = packageRunnerName(server.command, server.args);
  if (packageName !== undefined && !isPinnedPackage(packageName)) {
    findings.push(
      createFinding({
        idSeed: `${server.id}-${packageName}-unpinned`,
        severity: "medium",
        category: "mcp.config.unpinned_package",
        title: `${server.name} uses an unpinned package launcher`,
        description: "The MCP server is launched from a package name without a fixed version.",
        recommendation: "Pin the package version or use a reviewed local executable path.",
        target: server.name,
        evidence: [packageName]
      })
    );
  }

  findings.push(...scanSecretRecord(server, rawServer.env, "env"));
  findings.push(...scanSecretRecord(server, rawServer.headers, "headers"));

  if (server.transport === "sse") {
    findings.push(
      createFinding({
        idSeed: `${server.id}-sse`,
        severity: "medium",
        category: "mcp.config.deprecated_sse",
        title: `${server.name} uses SSE transport`,
        description: "SSE transport is deprecated in some MCP clients in favor of streamable HTTP.",
        recommendation: "Prefer streamable HTTP when the MCP server supports it.",
        target: server.name,
        evidence: server.url === undefined ? [] : [server.url]
      })
    );
  }

  if (server.url !== undefined && isPlainRemoteHttp(server.url)) {
    findings.push(
      createFinding({
        idSeed: `${server.id}-plain-http`,
        severity: "high",
        category: "mcp.config.plain_http",
        title: `${server.name} uses plain HTTP for a remote MCP server`,
        description: "Remote MCP traffic over HTTP can expose credentials and tool data in transit.",
        recommendation: "Use HTTPS for remote MCP servers, or keep plain HTTP limited to localhost development.",
        target: server.name,
        evidence: [server.url]
      })
    );
  }

  if (rawServer.trust === true) {
    findings.push(
      createFinding({
        idSeed: `${server.id}-trusted`,
        severity: "medium",
        category: "mcp.config.pretrusted_server",
        title: `${server.name} is marked trusted in config`,
        description: "Pre-trusting MCP servers can bypass a useful manual review checkpoint.",
        recommendation: "Keep trust disabled by default and approve servers after inspecting their command, URL, and permissions.",
        target: server.name
      })
    );
  }

  return findings;
}

function scanSecretRecord(server: ConfiguredMcpServer, values: Record<string, string>, label: "env" | "headers"): RiskFinding[] {
  return Object.entries(values)
    .filter(([key, value]) => isSensitiveKey(key) && isHardcodedSecret(value))
    .map(([key]) =>
      createFinding({
        idSeed: `${server.id}-${label}-${key}-hardcoded`,
        severity: "high",
        category: "mcp.config.hardcoded_secret",
        title: `${server.name} hardcodes sensitive ${label} value ${key}`,
        description: "The MCP server config appears to contain a literal credential instead of an environment reference.",
        recommendation: "Move secrets to environment variables or a managed secret store and reference them from config.",
        target: `${server.name}.${label}.${key}`
      })
    );
}

function inferTransport(server: RawServer): McpServerTransport {
  const type = server.type?.toLowerCase();
  if (type === "stdio") {
    return "stdio";
  }
  if (type === "http" || type === "streamable-http") {
    return "http";
  }
  if (type === "sse") {
    return "sse";
  }
  if (server.command !== undefined) {
    return "stdio";
  }
  if (server.url !== undefined) {
    return /\/sse(?:$|[/?#])/iu.test(server.url) ? "sse" : "http";
  }
  return "unknown";
}

function packageRunnerName(command: string | undefined, args: readonly string[]): string | undefined {
  if (command === undefined || !PACKAGE_RUNNERS.has(commandName(command))) {
    return undefined;
  }

  return args.find((arg) => !arg.startsWith("-") && !arg.includes("="));
}

function isPinnedPackage(packageName: string): boolean {
  if (packageName.endsWith("@latest")) {
    return false;
  }
  if (packageName.startsWith("@")) {
    return packageName.lastIndexOf("@") > 0;
  }
  return packageName.includes("@") || packageName.includes("==");
}

function isHardcodedSecret(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return false;
  }
  if (/^\$[A-Za-z_][A-Za-z0-9_]*$/u.test(trimmed) || /^\$\{[^}]+\}$/u.test(trimmed) || /^%[^%]+%$/u.test(trimmed)) {
    return false;
  }
  if (/^(<.+>|your[-_ ]|replace[-_ ]|changeme|example|dummy)/iu.test(trimmed)) {
    return false;
  }
  return true;
}

function isPlainRemoteHttp(url: string): boolean {
  if (!url.startsWith("http://")) {
    return false;
  }
  return !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:\/|$)/iu.test(url);
}

function inferClientFromPath(path: string): McpConfigClient {
  const normalized = path.replaceAll("\\", "/").toLowerCase();
  if (normalized.includes("/.codex/") || normalized.endsWith("/config.toml")) {
    return "codex";
  }
  if (normalized.includes("/.cursor/")) {
    return "cursor";
  }
  if (normalized.includes("/.vscode/") || normalized.includes("/code/user/")) {
    return "vscode";
  }
  if (normalized.includes("/.gemini/")) {
    return "gemini";
  }
  if (normalized.endsWith("/.claude.json")) {
    return "claude-code";
  }
  if (normalized.endsWith("/claude_desktop_config.json")) {
    return "claude-desktop";
  }
  return "unknown";
}

function detectFormat(path: string): McpConfigFormat {
  return path.toLowerCase().endsWith(".toml") ? "toml" : "json";
}

function parseTomlValue(value: string): string | string[] {
  const trimmed = value.trim();
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    return [...trimmed.matchAll(/"([^"]*)"/gu)].map((match) => match[1] ?? "");
  }
  const quoted = /^"([^"]*)"$/u.exec(trimmed);
  return quoted?.[1] ?? trimmed;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function stringRecord(value: unknown): Record<string, string> {
  if (!isRecord(value)) {
    return {};
  }

  return Object.fromEntries(Object.entries(value).filter((entry): entry is [string, string] => typeof entry[1] === "string"));
}

function commandName(command: string): string {
  return command.replaceAll("\\", "/").split("/").at(-1)?.toLowerCase() ?? command.toLowerCase();
}

function compareServers(left: ConfiguredMcpServer, right: ConfiguredMcpServer): number {
  return left.name.localeCompare(right.name) || left.sourcePath.localeCompare(right.sourcePath);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}
