# SARIF Export

Watchtower can export MCP and runtime attack graph findings as SARIF 2.1.0 for GitHub Code Scanning and other security tooling.

```bash
npx agentops-watchtower scan-mcp mcp-tools.json --sarif
npx agentops-watchtower inventory-mcp --sarif
npx agentops-watchtower admit-mcp --descriptor mcp-tools.json --config .mcp.json --sarif
npx agentops-watchtower analyze-run --trace trace.jsonl --sarif
```

Output:

```text
.watchtower/reports/watchtower.sarif
```

The SARIF exporter maps Watchtower findings into static-analysis results:

| Watchtower severity | SARIF level |
| --- | --- |
| `critical` | `error` |
| `high` | `error` |
| `medium` | `warning` |
| `low` | `warning` |
| `info` | `note` |

Each result includes:

- `ruleId` from the Watchtower finding category.
- a stable `partialFingerprints.watchtowerFindingId`.
- the descriptor URI when the scan command has a source file.
- severity, target, and evidence in SARIF `properties`.

## GitHub Code Scanning

Use the example workflow in `examples/github/watchtower-code-scanning.yml` as a starting point. It runs Watchtower, writes SARIF, and uploads it with `github/codeql-action/upload-sarif`.

For local validation:

```bash
npm run build
node dist/cli.js scan-mcp examples/mcp/safe-tools.json --sarif
```
