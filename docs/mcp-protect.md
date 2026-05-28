# MCP Protect Mode

`protect-mcp` is the adoption layer for the runtime proxy. It rewrites one selected MCP server entry so the client launches:

```text
npx -y agentops-watchtower@<version> proxy-mcp --config <upstream-config> --server <server>
```

This solves the practical problem after a scanner or proxy exists: developers still need a safe way to insert it into real MCP client configs and undo the change.

## Default Copy Mode

```bash
npx agentops-watchtower protect-mcp \
  --config .mcp.json \
  --server github \
  --descriptor mcp-tools.json
```

Copy mode does not edit the original config. It writes:

```text
.watchtower/protected/.mcp.protected.json
.watchtower/protected/.mcp.protection.json
```

Point your MCP client at the protected copy when you want the selected server to run behind Watchtower policy enforcement.

## In-Place Mode

```bash
npx agentops-watchtower protect-mcp --config .mcp.json --server github --in-place
```

In-place mode writes a backup first:

```text
.watchtower/protected/.mcp.backup.json
.watchtower/protected/.mcp.protection.json
```

The rewritten server points `proxy-mcp` at the backup file, not the modified original file. That prevents recursive proxy launches.

Restore from the manifest:

```bash
npx agentops-watchtower unprotect-mcp --config .mcp.json
```

## Supported Config Shape

v1.3 supports JSON client configs with `mcpServers` or `servers` maps. Unrelated config fields are preserved.

Example input:

```json
{
  "mcpServers": {
    "github": {
      "command": "node",
      "args": ["github-server.mjs"]
    }
  }
}
```

Protected output:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": [
        "-y",
        "agentops-watchtower@1.3.0",
        "proxy-mcp",
        "--config",
        "D:\\repo\\.mcp.json",
        "--server",
        "github"
      ]
    }
  }
}
```

## Guardrails

- Refuses to wrap a server that is already protected.
- Requires an explicit server name.
- Preserves unrelated config entries.
- Validates rollback manifests before restore.
- Keeps local files local; no cloud service or paid API is required.

## Boundaries

v1.3 protects JSON configs. TOML/YAML client configs, multi-server bulk wrapping, interactive approval prompts, and Streamable HTTP proxying remain later layers.
