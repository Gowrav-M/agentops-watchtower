# /watchtower-check

Run a local AgentOps Watchtower assessment without sending data to a cloud service.

Suggested command:

```bash
npx agentops-watchtower check --descriptor <mcp-tools.json> --trace <trace.jsonl> --firewall .watchtower/firewall.json
```

Keep the advanced commands available when deeper control is needed: `scan-mcp`, `inventory-mcp`, `analyze-run`, `firewall simulate`, `report`, and `attest-mcp`.
