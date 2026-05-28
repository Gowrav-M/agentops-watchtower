# Slash Commands

Watchtower keeps the full CLI available, but `setup` writes local slash-command templates so agent users can start from a small command surface.

```bash
npx agentops-watchtower setup
```

Generated templates are written to `.watchtower/slash-commands/`:

| Slash command | Default CLI action |
| --- | --- |
| `/watchtower-check` | `npx agentops-watchtower check --descriptor <mcp-tools.json> --trace <trace.jsonl> --firewall .watchtower/firewall.json` |
| `/watchtower-protect` | `npx agentops-watchtower protect --config <mcp-client.json> --server <server-name> --firewall .watchtower/firewall.json` |
| `/watchtower-report` | `npx agentops-watchtower report --analyze` |

These are templates, not a reduced product mode. Power users and CI should still call the exact commands they need: `scan-mcp`, `inventory-mcp`, `baseline-mcp`, `diff-mcp`, `admit-mcp`, `gate-mcp`, `firewall`, `proxy-mcp`, `protect-mcp`, `agent-bom`, `analyze-run`, `export-otel`, `attest-mcp`, and `verify-attestation`.

Use the tracked examples in [examples/slash-commands](../examples/slash-commands/) when configuring tools that support repository-level slash commands.
