# MCP Config Inventory

MCP risk often starts before a tool descriptor is ever scanned. Local client config can launch arbitrary commands, pull unpinned packages, or pass literal credentials to a server.

Watchtower v0.4 adds local MCP config inventory:

```bash
npx agentops-watchtower inventory-mcp
```

With no arguments, Watchtower checks common config locations for:

- Codex: `.codex/config.toml`, `~/.codex/config.toml`
- Claude Code: `.mcp.json`, `~/.claude.json`
- Claude Desktop: `Claude/claude_desktop_config.json` under the user app-data directory
- Cursor: `.cursor/mcp.json`, `~/.cursor/mcp.json`
- VS Code: `.vscode/mcp.json`, VS Code user `mcp.json`
- Gemini CLI: `.gemini/settings.json`, `~/.gemini/settings.json`

You can also scan explicit files:

```bash
npx agentops-watchtower inventory-mcp .mcp.json ~/.codex/config.toml --sarif --fail-on high
```

Output:

```text
.watchtower/reports/mcp-inventory.json
.watchtower/reports/watchtower.sarif
```

## Findings

| Category | Severity | Meaning |
| --- | --- | --- |
| `mcp.config.dangerous_shell` | critical | Shell installer or destructive command pattern such as `curl ... | sh`. |
| `mcp.config.shell_execution` | high | Server starts through a shell such as `bash`, `cmd`, or PowerShell. |
| `mcp.config.hardcoded_secret` | high | Sensitive env/header value appears to be literal instead of an env reference. |
| `mcp.config.plain_http` | high | Remote MCP URL uses plain HTTP outside localhost. |
| `mcp.config.unpinned_package` | medium | `npx` or `uvx` package launcher lacks a fixed version. |
| `mcp.config.deprecated_sse` | medium | Server uses SSE transport. |
| `mcp.config.pretrusted_server` | medium | Config marks the server trusted before review. |

This complements descriptor scanning. Inventory answers: "What MCP servers can this workstation start, and how risky is their launch path?"
