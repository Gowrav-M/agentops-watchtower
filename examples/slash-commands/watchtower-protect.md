# /watchtower-protect

Protect one configured stdio MCP server by routing it through the Watchtower proxy and optional Capability Firewall.

Suggested command:

```bash
npx agentops-watchtower protect --config <mcp-client.json> --server <server-name> --firewall .watchtower/firewall.json
```

Use `protect-mcp` directly when you need the full advanced flag surface.
