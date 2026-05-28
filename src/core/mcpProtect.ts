export interface McpProtectionManifest {
  schemaVersion: 1;
  protectedAt: string;
  mode: "copy" | "in-place";
  serverName: string;
  originalConfigPath: string;
  protectedConfigPath: string;
  backupConfigPath?: string;
  packageSpec: string;
  descriptorPath?: string;
  baselinePath?: string;
  firewallPath?: string;
  failOn?: string;
  originalServer: Record<string, unknown>;
  protectedServer: Record<string, unknown>;
}

export interface CreateMcpProtectionOptions {
  generatedAt?: string;
  serverName: string;
  originalConfigPath: string;
  protectedConfigPath: string;
  backupConfigPath?: string;
  packageSpec: string;
  descriptorPath?: string;
  baselinePath?: string;
  firewallPath?: string;
  failOn?: string;
}

export interface McpProtectionResult {
  protectedConfig: Record<string, unknown>;
  manifest: McpProtectionManifest;
}

interface ServerMapMatch {
  map: Record<string, unknown>;
  path: string;
}

export function createMcpProtection(config: unknown, options: CreateMcpProtectionOptions): McpProtectionResult {
  if (!isRecord(config)) {
    throw new Error("MCP config must be a JSON object.");
  }

  const protectedConfig = cloneRecord(config);
  const matches = collectServerMaps(protectedConfig).filter((candidate) => Object.hasOwn(candidate.map, options.serverName));
  if (matches.length === 0) {
    throw new Error(`MCP server not found: ${options.serverName}.`);
  }
  if (matches.length > 1) {
    throw new Error(`Multiple MCP server entries named ${options.serverName}; use a config with one matching server.`);
  }

  const match = matches[0];
  if (match === undefined) {
    throw new Error(`MCP server not found: ${options.serverName}.`);
  }

  const originalServer = match.map[options.serverName];
  if (!isRecord(originalServer)) {
    throw new Error(`MCP server ${options.serverName} is not a JSON object.`);
  }
  if (isProtectedServer(originalServer)) {
    throw new Error(`MCP server ${options.serverName} is already protected by Watchtower.`);
  }

  const upstreamConfigPath = options.backupConfigPath ?? options.originalConfigPath;
  const protectedServer = createProtectedServer(options, upstreamConfigPath);
  match.map[options.serverName] = protectedServer;

  return {
    protectedConfig,
    manifest: {
      schemaVersion: 1,
      protectedAt: options.generatedAt ?? new Date().toISOString(),
      mode: options.backupConfigPath === undefined ? "copy" : "in-place",
      serverName: options.serverName,
      originalConfigPath: options.originalConfigPath,
      protectedConfigPath: options.protectedConfigPath,
      ...(options.backupConfigPath === undefined ? {} : { backupConfigPath: options.backupConfigPath }),
      packageSpec: options.packageSpec,
      ...(options.descriptorPath === undefined ? {} : { descriptorPath: options.descriptorPath }),
      ...(options.baselinePath === undefined ? {} : { baselinePath: options.baselinePath }),
      ...(options.firewallPath === undefined ? {} : { firewallPath: options.firewallPath }),
      ...(options.failOn === undefined ? {} : { failOn: options.failOn }),
      originalServer: cloneRecord(originalServer),
      protectedServer
    }
  };
}

export function restoreMcpProtection(config: unknown, manifest: McpProtectionManifest): Record<string, unknown> {
  if (!isRecord(config)) {
    throw new Error("MCP config must be a JSON object.");
  }

  const restored = cloneRecord(config);
  const matches = collectServerMaps(restored).filter((candidate) => Object.hasOwn(candidate.map, manifest.serverName));
  if (matches.length === 0) {
    throw new Error(`MCP server not found: ${manifest.serverName}.`);
  }
  if (matches.length > 1) {
    throw new Error(`Multiple MCP server entries named ${manifest.serverName}; cannot restore safely.`);
  }
  const match = matches[0];
  if (match === undefined) {
    throw new Error(`MCP server not found: ${manifest.serverName}.`);
  }
  const currentServer = match.map[manifest.serverName];
  if (!isRecord(currentServer) || !isProtectedServer(currentServer)) {
    throw new Error(`MCP server ${manifest.serverName} is not currently protected by Watchtower.`);
  }
  match.map[manifest.serverName] = cloneRecord(manifest.originalServer);
  return restored;
}

function createProtectedServer(options: CreateMcpProtectionOptions, upstreamConfigPath: string): Record<string, unknown> {
  const args = [
    "-y",
    options.packageSpec,
    "proxy-mcp",
    "--config",
    upstreamConfigPath,
    "--server",
    options.serverName
  ];
  if (options.descriptorPath !== undefined) {
    args.push("--descriptor", options.descriptorPath);
  }
  if (options.baselinePath !== undefined) {
    args.push("--baseline", options.baselinePath);
  }
  if (options.firewallPath !== undefined) {
    args.push("--firewall", options.firewallPath);
  }
  if (options.failOn !== undefined) {
    args.push("--fail-on", options.failOn);
  }

  return {
    command: "npx",
    args
  };
}

function collectServerMaps(value: unknown, path = "$"): ServerMapMatch[] {
  if (!isRecord(value)) {
    return [];
  }

  const maps: ServerMapMatch[] = [];
  const mcpServers = value["mcpServers"];
  const servers = value["servers"];
  if (isRecord(mcpServers)) {
    maps.push({ map: mcpServers, path: `${path}.mcpServers` });
  }
  if (isRecord(servers)) {
    maps.push({ map: servers, path: `${path}.servers` });
  }

  for (const [key, child] of Object.entries(value)) {
    if (isRecord(child) || Array.isArray(child)) {
      maps.push(...collectServerMaps(child, `${path}.${key}`));
    }
  }
  return maps;
}

function isProtectedServer(server: Record<string, unknown>): boolean {
  return server["command"] === "npx" && Array.isArray(server["args"]) && server["args"].includes("proxy-mcp");
}

function cloneRecord(value: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
