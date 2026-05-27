# OpenTelemetry Export

Watchtower exports local runs as OpenTelemetry-style span JSON:

```bash
npx agentops-watchtower export-otel
```

Output:

```text
.watchtower/reports/otel-spans.json
```

The exporter is dependency-free and writes portable JSON rather than sending telemetry anywhere. It uses GenAI/MCP semantic attribute names where they fit:

- `gen_ai.operation.name`
- `gen_ai.agent.name`
- `gen_ai.tool.name`
- `mcp.method.name`
- `mcp.server.name`

Agent runs become `invoke_agent` spans. Tool calls become `tools/call {tool}` spans with `gen_ai.operation.name = execute_tool`.

This gives teams a migration path toward full OpenTelemetry collectors without forcing a backend in the first release.
