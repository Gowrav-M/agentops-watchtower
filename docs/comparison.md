# Comparison

AgentOps Watchtower is designed to sit between lightweight inspectors and full observability platforms.

| Tool class | Strength | Gap Watchtower targets |
| --- | --- | --- |
| MCP inspectors | Great for manual tool testing and descriptor inspection. | Less focused on reproducible local AgentOps reports and transcript evals. |
| LLM observability platforms | Strong tracing, dashboards, prompt/eval workflows. | Often require service setup, SDK instrumentation, or cloud/team accounts. |
| Security checklists | Useful review guidance. | Usually not executable against local descriptors and traces. |
| Static analysis platforms | Excellent at centralizing findings through SARIF/code scanning. | Usually do not understand MCP tool metadata, agent traces, or tool drift. |
| Agent frameworks | Build and run agents. | Do not always explain what a run did or whether tool descriptors are safe. |
| MCP firewalls/proxies | Enforce some calls in the runtime path. | Usually require a hosted gateway or early proxy install; Watchtower can generate local policy, simulate it from traces, reconstruct risk paths, and create protected config wrappers. |

Watchtower's first release focuses on a small, installable workflow:

```bash
agentops-watchtower import trace.jsonl
agentops-watchtower scan-mcp tools.json --sarif
agentops-watchtower baseline-mcp tools.json
agentops-watchtower diff-mcp tools.json
agentops-watchtower inventory-mcp
agentops-watchtower agent-bom --config .mcp.json --descriptor tools.json --cyclonedx
agentops-watchtower admit-mcp --descriptor tools.json --config .mcp.json
agentops-watchtower gate-mcp --config .mcp.json --server github --descriptor tools.json
agentops-watchtower firewall init --descriptor tools.json
agentops-watchtower firewall simulate --config .watchtower/firewall.json --trace trace.jsonl
agentops-watchtower proxy-mcp --config .mcp.json --server github --descriptor tools.json --firewall .watchtower/firewall.json
agentops-watchtower protect-mcp --config .mcp.json --server github --descriptor tools.json --firewall .watchtower/firewall.json
agentops-watchtower analyze-run --trace trace.jsonl --sarif
agentops-watchtower attest-mcp --subject reviewed-mcp
agentops-watchtower report --mcp tools.json --analyze
agentops-watchtower export-otel
```

The output is designed for PR reviews, app submissions, internal security checks, and personal debugging.
