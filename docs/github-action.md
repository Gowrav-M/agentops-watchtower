# GitHub Action

Watchtower ships a composite GitHub Action at the repository root.

```yaml
- name: Run Watchtower
  uses: Gowrav-M/agentops-watchtower@v1
  with:
    descriptor: examples/mcp/safe-tools.json
    config: examples/mcp/safe-client-config.json
    fail-on: high
    run-agent-bom: "true"
    run-admission: "true"
    run-proxy-dry-run: "false"
```

The action runs the npm package through `npx`, writes Watchtower artifacts under `.watchtower/reports/`, and appends a short summary to the GitHub job summary.
By default it also generates a Markdown/HTML/JSON report and an unsigned tamper-evident evidence bundle.

## Outputs

- `report-json`: `.watchtower/reports/watchtower-report.json`
- `sarif`: `.watchtower/reports/watchtower.sarif`
- `agent-bom`: `.watchtower/reports/agent-bom.json`
- `evidence-bundle`: `.watchtower/reports/evidence-bundle.json`
- `proxy-audit`: `.watchtower/reports/mcp-proxy-audit.json`

## SARIF Upload

Use the example in `examples/github/watchtower-action.yml` to upload Watchtower SARIF to GitHub Code Scanning:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: .watchtower/reports/watchtower.sarif
    category: agentops-watchtower
```

## Notes

The action assumes the `agentops-watchtower` npm package is available. Use `package-version` to pin a published version instead of `latest`.
Set `run-report` or `run-attestation` to `"false"` only when another workflow step creates those artifacts.
Set `run-proxy-dry-run` to `"true"` with `config` and `server` when you want CI to verify that a selected stdio MCP server can pass the proxy preflight without launching it.
