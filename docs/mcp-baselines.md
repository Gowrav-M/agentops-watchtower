# MCP Baselines

MCP descriptors are part of the agent trust boundary. A tool can look safe during review and later change its description, schema, or annotations in a way that influences the agent.

Watchtower v0.3 adds deterministic MCP baselines:

```bash
npx agentops-watchtower baseline-mcp mcp-tools.json
npx agentops-watchtower diff-mcp mcp-tools.json --fail-on high
```

The baseline is written to:

```text
.watchtower/baselines/mcp-tools.json
```

## What Is Fingerprinted

For each MCP tool, Watchtower hashes:

- tool name
- description
- input schema
- output schema
- annotations

The JSON is canonicalized before hashing, so object key ordering does not create false drift.

## Drift Findings

| Category | Severity | Meaning |
| --- | --- | --- |
| `mcp.baseline.added` | high | A new tool exists that was not approved. |
| `mcp.baseline.changed` | critical | An approved tool changed its descriptor fingerprint. |
| `mcp.baseline.removed` | medium | An approved tool disappeared from the current descriptor. |

This is designed for CI. Commit an approved baseline, then fail pull requests or scheduled checks when current MCP descriptors drift unexpectedly.
