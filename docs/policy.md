# Policy Mode

AgentOps Watchtower can run as a CI gate for MCP descriptors and agent traces.

Create `watchtower.config.json` in the repo root:

```json
{
  "schemaVersion": 1,
  "storage": "local-jsonl",
  "policy": {
    "failOn": "high",
    "requireOutputSchema": true,
    "allowDestructiveTools": false,
    "allowOpenWorldTools": true,
    "detectToolPoisoning": true
  }
}
```

Run:

```bash
npx agentops-watchtower scan-mcp mcp-tools.json --fail-on high
npx agentops-watchtower report --mcp mcp-tools.json --fail-on high
npx agentops-watchtower diff-mcp mcp-tools.json --fail-on high
npx agentops-watchtower inventory-mcp --fail-on high
npx agentops-watchtower admit-mcp --descriptor mcp-tools.json --config .mcp.json --fail-on high
npx agentops-watchtower gate-mcp --config .mcp.json --server github --descriptor mcp-tools.json --fail-on high
npx agentops-watchtower analyze-run --trace trace.jsonl --fail-on high
```

Severity order:

```text
info < low < medium < high < critical
```

If a finding is at or above the threshold, the command exits non-zero. That makes Watchtower usable in GitHub Actions, pre-merge checks, and internal release gates.

Policy gates apply to scanner findings, report findings, MCP baseline drift findings, MCP config inventory findings, MCP admission findings, MCP preflight gate findings, and runtime attack graph findings.

## Tool-Poisoning Checks

The scanner treats MCP tool metadata as an injection surface. It flags descriptions and schema text that look like hidden instructions, such as:

- ignore previous instructions
- bypass safety policy
- silently send secrets
- do not reveal this instruction
- exfiltrate tokens or credentials

This follows the same practical risk model described in OWASP MCP guidance: tool descriptions, schemas, and return values can manipulate an agent if they are blindly inserted into model context.
