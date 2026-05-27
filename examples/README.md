# Examples

## MCP descriptors

- `mcp/safe-tools.json`: one low-risk read-only tool.
- `mcp/risky-tools.json`: examples with destructive behavior, open-world behavior, missing output schemas, and sensitive input fields.

## Traces

- `traces/codex-session.jsonl`: normalized JSONL-style agent session.
- `traces/claude-session.md`: Markdown transcript import example.

Run:

```bash
npm run dev -- demo
npm run dev -- scan-mcp examples/mcp/risky-tools.json --sarif
npm run dev -- baseline-mcp examples/mcp/safe-tools.json
npm run dev -- diff-mcp examples/mcp/safe-tools.json
npm run dev -- import examples/traces/codex-session.jsonl
npm run dev -- report --mcp examples/mcp/risky-tools.json
npm run dev -- export-otel
```

## GitHub

- `github/watchtower-code-scanning.yml`: example workflow for uploading Watchtower SARIF to GitHub Code Scanning.
