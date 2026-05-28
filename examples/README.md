# Examples

## MCP descriptors

- `mcp/safe-tools.json`: one low-risk read-only tool.
- `mcp/risky-tools.json`: examples with destructive behavior, open-world behavior, missing output schemas, and sensitive input fields.
- `mcp/safe-client-config.json`: one low-risk MCP client config.
- `mcp/sample-client-config.json`: MCP client config with a dangerous shell installer.
- `mcp/stdio-client-config.json`: local stdio MCP config for proxy dry-runs.
- `mcp/stdio-echo-server.mjs`: tiny stdio JSON-RPC echo server used by proxy examples.
- `firewall/least-privilege.json`: sample Capability Firewall policy with allow, deny, and escalation rules.
- `slash-commands/`: repository-level templates for `/watchtower-check`, `/watchtower-protect`, and `/watchtower-report`.

## Traces

- `traces/codex-session.jsonl`: normalized JSONL-style agent session.
- `traces/source-to-sink.jsonl`: runtime attack graph fixture with a secret-like source and external sink.
- `traces/firewall-violation.jsonl`: trace fixture for Capability Firewall simulation.
- `traces/claude-session.md`: Markdown transcript import example.

Run:

```bash
npm run dev -- demo
npm run dev -- setup --descriptor examples/mcp/risky-tools.json
npm run dev -- check --descriptor examples/mcp/safe-tools.json --trace examples/traces/firewall-violation.jsonl --firewall examples/firewall/least-privilege.json
npm run dev -- protect --config examples/mcp/stdio-client-config.json --server local-echo --firewall examples/firewall/least-privilege.json
npm run dev -- scan-mcp examples/mcp/risky-tools.json --sarif
npm run dev -- baseline-mcp examples/mcp/safe-tools.json
npm run dev -- diff-mcp examples/mcp/safe-tools.json
npm run dev -- inventory-mcp examples/mcp/sample-client-config.json --sarif
npm run dev -- agent-bom --config examples/mcp/safe-client-config.json --descriptor examples/mcp/safe-tools.json --cyclonedx
npm run dev -- admit-mcp --descriptor examples/mcp/safe-tools.json --config examples/mcp/safe-client-config.json --sarif
npm run dev -- gate-mcp --config examples/mcp/safe-client-config.json --server safe-docs --descriptor examples/mcp/safe-tools.json --sarif
npm run dev -- firewall init --descriptor examples/mcp/risky-tools.json
npm run dev -- firewall simulate --config examples/firewall/least-privilege.json --trace examples/traces/firewall-violation.jsonl
npm run dev -- proxy-mcp --config examples/mcp/stdio-client-config.json --server local-echo --dry-run --firewall examples/firewall/least-privilege.json
npm run dev -- protect-mcp --config examples/mcp/stdio-client-config.json --server local-echo --firewall examples/firewall/least-privilege.json
npm run dev -- analyze-run --trace examples/traces/source-to-sink.jsonl --sarif
npm run dev -- attest-mcp --subject safe-docs --private-key private.pem --key-id local-reviewer
npm run dev -- verify-attestation --public-key public.pem
npm run dev -- import examples/traces/codex-session.jsonl
npm run dev -- report --mcp examples/mcp/risky-tools.json --analyze
npm run dev -- export-otel
```

## GitHub

- `github/watchtower-code-scanning.yml`: example workflow for uploading Watchtower SARIF to GitHub Code Scanning.
- `github/watchtower-action.yml`: example workflow using the packaged Watchtower GitHub Action.
