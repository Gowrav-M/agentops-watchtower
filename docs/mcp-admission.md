# MCP Admission Gate

`admit-mcp` turns Watchtower's individual checks into one admission decision:

```bash
npx agentops-watchtower admit-mcp \
  --descriptor mcp-tools.json \
  --config .mcp.json \
  --baseline .watchtower/baselines/mcp-tools.json \
  --sarif \
  --fail-on high
```

Output:

```text
.watchtower/reports/mcp-admission.json
.watchtower/reports/watchtower.sarif
```

## Decision Model

| Decision | Condition | Meaning |
| --- | --- | --- |
| `allow` | no medium, high, or critical findings | Server can be enabled within the reviewed scope. |
| `review` | medium or high findings | Human review is required before enabling the server. |
| `deny` | critical findings | Server should be blocked until fixed. |

## Checks

The admission report can combine:

- `config-inventory`: MCP client launch config risk.
- `descriptor-scan`: MCP tool descriptor risk.
- `baseline-diff`: descriptor drift from an approved baseline.

This is the local-first control-plane shape: scan what the server can do, inspect how it starts, compare against what was approved, then emit a machine-readable decision for CI or review.
