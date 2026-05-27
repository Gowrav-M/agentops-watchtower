# AgentOps Watchtower

Local-first black box recorder, MCP safety scanner, and eval report generator for AI agent workflows.

AgentOps Watchtower is for developers using Codex, Claude Code, OpenCode, OpenClaw, Hermes Agent, Cursor, and MCP servers who need to answer one question quickly:

> What did the agent do, which tools were risky, and what should be fixed before this workflow is trusted?

It is not another agent framework. It is an operations layer for agent runs: import traces, scan MCP tool descriptors, run deterministic evals, and generate reproducible Markdown, HTML, and JSON reports.

## Quick Start

```bash
npx agentops-watchtower demo
```

Local development:

```bash
npm install
npm run build
node dist/cli.js demo
```

The demo writes local files under `.watchtower/`:

- `.watchtower/runs/runs.jsonl`
- `.watchtower/reports/watchtower-report.md`
- `.watchtower/reports/watchtower-report.html`
- `.watchtower/reports/watchtower-report.json`
- `.watchtower/reports/mcp-scan.json`
- `.watchtower/reports/otel-spans.json`

No paid API is required. No trace data leaves your machine.

## CLI

```bash
agentops-watchtower init
agentops-watchtower import examples/traces/codex-session.jsonl
agentops-watchtower scan-mcp examples/mcp/risky-tools.json
agentops-watchtower eval
agentops-watchtower report --mcp examples/mcp/risky-tools.json
agentops-watchtower export-otel
agentops-watchtower doctor
```

### Commands

| Command | Purpose |
| --- | --- |
| `init` | Creates `.watchtower/` local config and storage folders. |
| `demo` | Runs the bundled trace and MCP descriptor examples. |
| `import <trace>` | Imports JSONL, NDJSON, Markdown, or text transcripts into normalized local JSONL. |
| `scan-mcp [descriptor]` | Scans MCP descriptors for risky annotations, missing schemas, sensitive inputs, and weak descriptions. |
| `eval` | Runs deterministic checks against imported agent runs. |
| `report` | Generates Markdown, HTML, and JSON reports from local runs plus optional MCP findings. |
| `export-otel` | Exports local runs as OpenTelemetry-style GenAI/MCP span JSON. |
| `doctor` | Checks Node version, write access, and local config shape. |

## What It Detects

- Missing MCP annotations: `readOnlyHint`, `destructiveHint`, `openWorldHint`.
- Destructive tool names/descriptions whose annotations understate risk.
- Open-world tools that can send, publish, deploy, or affect external systems.
- Missing `outputSchema`.
- Sensitive input fields such as API keys, tokens, passwords, secrets, MFA, or private keys.
- Tool-poisoning patterns hidden in descriptions and schemas.
- Failed agent steps and risky tool calls in imported traces.
- Unredacted secret-looking arguments in tool call records.

## CI Policy Mode

Use Watchtower as a failing CI gate:

```bash
npx agentops-watchtower scan-mcp examples/mcp/risky-tools.json --fail-on high
npx agentops-watchtower report --mcp examples/mcp/risky-tools.json --fail-on high
```

The optional `watchtower.config.json` file controls defaults:

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

See [docs/policy.md](docs/policy.md).

## OpenTelemetry Export

```bash
npx agentops-watchtower export-otel
```

The exporter writes `.watchtower/reports/otel-spans.json` using GenAI/MCP semantic attribute names such as `gen_ai.operation.name`, `gen_ai.tool.name`, and `mcp.method.name`. See [docs/opentelemetry.md](docs/opentelemetry.md).

## Trace Format

JSONL records are intentionally simple:

```jsonl
{"type":"session","id":"demo-codex-run","agent":"codex","startedAt":"2026-05-27T10:00:00.000Z","goal":"Inspect an MCP server before submission"}
{"type":"step","id":"step-1","timestamp":"2026-05-27T10:00:02.000Z","role":"assistant","summary":"Loaded MCP tool descriptors","status":"completed"}
{"type":"tool_call","id":"tool-1","stepId":"step-1","timestamp":"2026-05-27T10:00:03.000Z","toolName":"list_projects","arguments":{"workspaceId":"demo","apiKey":"demo-secret"},"status":"success"}
```

Secret-looking argument fields are redacted during import.

## Why This Exists

Agent ecosystems are moving fast: MCP servers, skills, coding agents, memory systems, evals, and local automation are becoming normal developer infrastructure. Teams need a small local tool that can inspect the practical risk surface before adopting or shipping agent workflows.

AgentOps Watchtower focuses on the useful middle ground:

- smaller than a full observability platform,
- broader than a single MCP inspector,
- safer than raw transcript sharing,
- easy to run in CI or locally.

## Development

```bash
npm install
npm run typecheck
npm test
npm run lint
npm run build
node dist/cli.js demo
```

## Project Status

This is v0.2: local JSONL storage, deterministic evals, MCP descriptor scanning, policy gates, tool-poisoning checks, OpenTelemetry-style span export, and static reports. Planned next steps:

- SQLite storage.
- More agent transcript adapters.
- MCP server wrapper mode.
- GitHub Action summary comments.
- Browser-based local report viewer.

## License

MIT
