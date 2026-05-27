# Agent Bill of Materials

`agent-bom` creates a local inventory artifact for agent and MCP governance. It is the Watchtower answer to shadow agent infrastructure:

> Which MCP configs, servers, tools, fingerprints, annotations, and findings exist in this workspace?

## Usage

```bash
npx agentops-watchtower agent-bom \
  --config .mcp.json \
  --descriptor mcp-tools.json \
  --cyclonedx
```

Output:

```text
.watchtower/reports/agent-bom.json
.watchtower/reports/agent-bom.md
.watchtower/reports/agent-bom.cdx.json
```

## What It Contains

The Watchtower AgentBOM includes:

- MCP config sources and parse status.
- Configured MCP servers, transports, client scope, env key names, and per-server finding counts.
- MCP tool descriptors, annotations, schema presence, and deterministic fingerprints.
- Inventory and descriptor findings with severity counts.

The CycloneDX-compatible export represents configs, MCP servers, and MCP tools as components with Watchtower properties. It is intentionally dependency-free and designed to be ingested by teams already using SBOM-style workflows.

## Why It Matters

Security teams cannot govern agent systems they cannot inventory. MCP servers can appear in local IDE config, user profile config, project files, or CI setup. AgentBOM gives the team a portable snapshot of that surface so it can be attached to reviews, tickets, release approvals, and evidence bundles.
