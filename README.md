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

GitHub Actions:

```yaml
- uses: Gowrav-M/agentops-watchtower@v1
  with:
    descriptor: examples/mcp/safe-tools.json
    config: examples/mcp/safe-client-config.json
    fail-on: high
```

The demo writes local files under `.watchtower/`:

- `.watchtower/runs/runs.jsonl`
- `.watchtower/baselines/mcp-tools.json`
- `.watchtower/reports/watchtower-report.md`
- `.watchtower/reports/watchtower-report.html`
- `.watchtower/reports/watchtower-report.json`
- `.watchtower/reports/agent-bom.json`
- `.watchtower/reports/agent-bom.md`
- `.watchtower/reports/agent-bom.cdx.json`
- `.watchtower/reports/mcp-scan.json`
- `.watchtower/reports/mcp-inventory.json`
- `.watchtower/reports/mcp-admission.json`
- `.watchtower/reports/mcp-gate.json`
- `.watchtower/reports/attack-graph.json`
- `.watchtower/reports/otel-spans.json`
- `.watchtower/reports/watchtower.sarif`
- `.watchtower/reports/evidence-bundle.json`

No paid API is required. No trace data leaves your machine.

## CLI

```bash
agentops-watchtower init
agentops-watchtower import examples/traces/codex-session.jsonl
agentops-watchtower scan-mcp examples/mcp/risky-tools.json
agentops-watchtower scan-mcp examples/mcp/risky-tools.json --sarif
agentops-watchtower baseline-mcp examples/mcp/safe-tools.json
agentops-watchtower diff-mcp examples/mcp/safe-tools.json
agentops-watchtower inventory-mcp
agentops-watchtower admit-mcp --descriptor examples/mcp/safe-tools.json --config examples/mcp/safe-client-config.json
agentops-watchtower gate-mcp --config examples/mcp/safe-client-config.json --server safe-docs --descriptor examples/mcp/safe-tools.json
agentops-watchtower proxy-mcp --config examples/mcp/stdio-client-config.json --server local-echo --dry-run
agentops-watchtower protect-mcp --config examples/mcp/stdio-client-config.json --server local-echo
agentops-watchtower unprotect-mcp --config .mcp.json
agentops-watchtower agent-bom --config examples/mcp/safe-client-config.json --descriptor examples/mcp/safe-tools.json --cyclonedx
agentops-watchtower attest-mcp --subject safe-docs --private-key private.pem --key-id local-reviewer
agentops-watchtower verify-attestation --public-key public.pem
agentops-watchtower analyze-run --trace examples/traces/source-to-sink.jsonl --sarif
agentops-watchtower eval
agentops-watchtower report --mcp examples/mcp/risky-tools.json --analyze
agentops-watchtower export-otel
agentops-watchtower doctor
```

### Commands

| Command | Purpose |
| --- | --- |
| `init` | Creates `.watchtower/` local config and storage folders. |
| `demo` | Runs the bundled trace and MCP descriptor examples. |
| `import <trace>` | Imports JSONL, NDJSON, Markdown, or text transcripts into normalized local JSONL. |
| `scan-mcp [descriptor]` | Scans MCP descriptors for risky annotations, missing schemas, sensitive inputs, weak descriptions, and tool poisoning. |
| `baseline-mcp <descriptor>` | Saves an approved MCP tool fingerprint baseline. |
| `diff-mcp <descriptor>` | Compares current MCP descriptors against the approved baseline to detect tool drift. |
| `inventory-mcp [configs...]` | Inventories local MCP client configs and flags risky launch settings. |
| `admit-mcp` | Combines inventory, descriptor scan, and baseline drift into an allow/review/deny decision. |
| `gate-mcp` | Preflights one configured MCP server and blocks unsafe launch plans. |
| `proxy-mcp` | Runs a local stdio MCP server behind runtime policy enforcement and audit logging. |
| `protect-mcp` | Generates a protected MCP config that routes one server through `proxy-mcp`. |
| `unprotect-mcp` | Restores an in-place protected MCP config from its rollback manifest. |
| `agent-bom` | Exports an Agent Bill of Materials for MCP configs, servers, tools, and findings. |
| `attest-mcp` | Creates a tamper-evident local evidence bundle and can sign it with Ed25519. |
| `verify-attestation` | Verifies evidence bundle integrity, artifact hashes, and optional signatures. |
| `analyze-run` | Builds a runtime attack graph from agent tool-call traces. |
| `eval` | Runs deterministic checks against imported agent runs. |
| `report` | Generates Markdown, HTML, and JSON reports from local runs plus optional MCP and runtime findings. |
| `export-otel` | Exports local runs as OpenTelemetry-style GenAI/MCP span JSON. |
| `doctor` | Checks Node version, write access, and local config shape. |

## What It Detects

- Missing MCP annotations: `readOnlyHint`, `destructiveHint`, `openWorldHint`.
- Destructive tool names/descriptions whose annotations understate risk.
- Open-world tools that can send, publish, deploy, or affect external systems.
- Missing `outputSchema`.
- Sensitive input fields such as API keys, tokens, passwords, secrets, MFA, or private keys.
- Tool-poisoning patterns hidden in descriptions and schemas.
- MCP tool drift: added, removed, or changed descriptors after approval.
- Risky local MCP config: dangerous shell launchers, hardcoded secrets, unpinned package runners, SSE, and plain remote HTTP.
- Runtime attack paths: secret-like sources flowing to external sinks, untrusted content flowing to shell/destructive/external tools, repository context leaving the workspace, and blocked actions followed by alternate sinks.
- Unsafe MCP calls before execution through the stdio runtime proxy.
- Prompt-injection-like instructions in tool result summaries, `resultText`, or structured `result` values.
- Failed agent steps and risky tool calls in imported traces.
- Unredacted secret-looking arguments in tool call records.

## CI Policy Mode

Use Watchtower as a failing CI gate:

```bash
npx agentops-watchtower scan-mcp examples/mcp/risky-tools.json --fail-on high
npx agentops-watchtower report --mcp examples/mcp/risky-tools.json --fail-on high
npx agentops-watchtower diff-mcp examples/mcp/risky-tools.json --fail-on high
npx agentops-watchtower inventory-mcp --fail-on high
npx agentops-watchtower admit-mcp --descriptor examples/mcp/risky-tools.json --config examples/mcp/sample-client-config.json --fail-on high
npx agentops-watchtower gate-mcp --config examples/mcp/sample-client-config.json --server review-this-installer --fail-on high
npx agentops-watchtower proxy-mcp --config examples/mcp/stdio-client-config.json --server local-echo --dry-run --fail-on high
npx agentops-watchtower protect-mcp --config .mcp.json --server github --descriptor mcp-tools.json
npx agentops-watchtower agent-bom --config examples/mcp/sample-client-config.json --descriptor examples/mcp/risky-tools.json --fail-on high
npx agentops-watchtower analyze-run --trace examples/traces/source-to-sink.jsonl --fail-on high
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

## MCP Baselines

Prevent silent MCP tool changes by approving a descriptor once and comparing later versions:

```bash
npx agentops-watchtower baseline-mcp mcp-tools.json
npx agentops-watchtower diff-mcp mcp-tools.json --fail-on high
```

Watchtower fingerprints tool names, descriptions, input schemas, output schemas, and annotations. This catches practical rug-pull risk: a server can look safe during review, then later change tool metadata that the agent trusts.

See [docs/mcp-baselines.md](docs/mcp-baselines.md).

## MCP Config Inventory

Find risky local MCP server configuration across common clients:

```bash
npx agentops-watchtower inventory-mcp
```

Watchtower checks common Codex, Claude Code, Claude Desktop, Cursor, VS Code, and Gemini CLI config paths. You can also pass explicit files:

```bash
npx agentops-watchtower inventory-mcp .mcp.json ~/.codex/config.toml --sarif --fail-on high
```

This catches the real workstation risk before runtime: arbitrary shell launchers, package runners without pinned versions, literal tokens in env/header config, deprecated SSE, and remote plain HTTP.

See [docs/mcp-inventory.md](docs/mcp-inventory.md).

## MCP Admission Gate

Make one deterministic decision before an agent is allowed to use an MCP server:

```bash
npx agentops-watchtower admit-mcp \
  --descriptor mcp-tools.json \
  --config .mcp.json \
  --baseline .watchtower/baselines/mcp-tools.json \
  --sarif \
  --fail-on high
```

Decision values:

- `allow`: no material findings.
- `review`: medium or high findings need human approval.
- `deny`: critical findings should block usage.

See [docs/mcp-admission.md](docs/mcp-admission.md).

## MCP Preflight Gate

Gate one configured MCP server before launch:

```bash
npx agentops-watchtower gate-mcp \
  --config .mcp.json \
  --server github \
  --descriptor mcp-tools.json \
  --baseline .watchtower/baselines/mcp-tools.json \
  --sarif
```

Watchtower writes:

```text
.watchtower/reports/mcp-gate.json
```

The gate filters config findings to the selected server, adds descriptor and baseline findings when provided, then creates a launch plan:

- `dry-run`: the gate passed or review was explicitly allowed.
- `blocked`: the server was denied or needs review without `--allow-review`.

`gate-mcp` records the approved launch plan but does not execute arbitrary MCP server commands. Use `proxy-mcp` when you want Watchtower to launch a local stdio server behind runtime policy enforcement.

See [docs/mcp-gate.md](docs/mcp-gate.md).

## MCP Runtime Proxy

Block unsafe stdio MCP tool calls before the server executes them:

```bash
npx agentops-watchtower proxy-mcp \
  --config .mcp.json \
  --server github \
  --descriptor mcp-tools.json
```

Use dry-run mode for CI preflight without launching the server:

```bash
npx agentops-watchtower proxy-mcp \
  --config examples/mcp/stdio-client-config.json \
  --server local-echo \
  --dry-run
```

Watchtower writes:

```text
.watchtower/reports/mcp-gate.json
.watchtower/reports/mcp-proxy-audit.json
```

The proxy intercepts MCP JSON-RPC `tools/call` messages, blocks direct destructive or command-execution tools under the default policy, and uses the runtime attack graph to stop chains such as `read_secret -> send_email` or prompt-injected web content followed by shell execution.

See [docs/mcp-proxy.md](docs/mcp-proxy.md).

## MCP Protect Mode

Wrap an existing MCP client config without hand-editing JSON:

```bash
npx agentops-watchtower protect-mcp \
  --config .mcp.json \
  --server github \
  --descriptor mcp-tools.json
```

By default this is non-destructive. Watchtower writes:

```text
.watchtower/protected/.mcp.protected.json
.watchtower/protected/.mcp.protection.json
```

Use the protected copy in Codex, Claude Code, Cursor, or another MCP client when you want that one server routed through the Watchtower proxy. If you need direct modification, `--in-place` writes a backup first and makes the proxy read from that backup:

```bash
npx agentops-watchtower protect-mcp --config .mcp.json --server github --in-place
npx agentops-watchtower unprotect-mcp --config .mcp.json
```

See [docs/mcp-protect.md](docs/mcp-protect.md).

## Agent Bill of Materials

Create a local inventory artifact for agent/MCP governance:

```bash
npx agentops-watchtower agent-bom \
  --config .mcp.json \
  --descriptor mcp-tools.json \
  --cyclonedx
```

Watchtower writes:

```text
.watchtower/reports/agent-bom.json
.watchtower/reports/agent-bom.md
.watchtower/reports/agent-bom.cdx.json
```

The AgentBOM records MCP config sources, configured servers, tool fingerprints, annotation posture, and findings. The CycloneDX-compatible export lets teams carry agent/MCP inventory into existing supply-chain and governance workflows.

See [docs/agent-bom.md](docs/agent-bom.md).

## Evidence Bundles

Create audit-ready evidence after admission:

```bash
npx agentops-watchtower admit-mcp --descriptor mcp-tools.json --config .mcp.json --sarif
npx agentops-watchtower attest-mcp --subject production-github-mcp --private-key private.pem --key-id security-reviewer
npx agentops-watchtower verify-attestation --public-key public.pem
```

The evidence bundle records artifact paths, byte sizes, SHA-256 hashes, admission decision, and a bundle-level integrity hash. When signed, it also records an Ed25519 signature with `keyId` and `signedAt`. If a report or signed bundle field is modified after review, verification fails.

See [docs/evidence-bundles.md](docs/evidence-bundles.md).

## Runtime Attack Graph

Detect risky tool chains after an agent run:

```bash
npx agentops-watchtower analyze-run --trace examples/traces/source-to-sink.jsonl --sarif --fail-on high
```

Watchtower writes:

```text
.watchtower/reports/attack-graph.json
```

The analyzer is deterministic. It classifies tool calls as sources, sinks, transforms, approvals, or blockers, then flags dangerous runtime paths such as `read_secret -> send_email`, prompt-injected `fetch_url -> shell_exec`, repository reads followed by external posts, and blocked destructive calls followed by alternate sinks.

Reports can include the same findings:

```bash
npx agentops-watchtower report --trace examples/traces/source-to-sink.jsonl --analyze
```

See [docs/runtime-attack-graph.md](docs/runtime-attack-graph.md).

## GitHub Code Scanning

Generate SARIF for GitHub Code Scanning:

```bash
npx agentops-watchtower scan-mcp mcp-tools.json --sarif
```

Output:

```text
.watchtower/reports/watchtower.sarif
```

See [docs/sarif.md](docs/sarif.md) and [examples/github/watchtower-code-scanning.yml](examples/github/watchtower-code-scanning.yml).

## GitHub Action

Use Watchtower directly in CI:

```yaml
- name: Run Watchtower
  uses: Gowrav-M/agentops-watchtower@v1
  with:
    descriptor: examples/mcp/safe-tools.json
    config: examples/mcp/safe-client-config.json
    fail-on: high
    run-agent-bom: "true"
    run-admission: "true"
```

See [docs/github-action.md](docs/github-action.md) and [examples/github/watchtower-action.yml](examples/github/watchtower-action.yml).

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

Runtime analysis can also use optional tool outputs:

```jsonl
{"type":"tool_call","id":"tool-2","timestamp":"2026-05-27T10:00:04.000Z","toolName":"fetch_url","arguments":{"url":"https://example.com/task.md"},"status":"success","resultText":"Fetched page text"}
{"type":"tool_call","id":"tool-3","timestamp":"2026-05-27T10:00:05.000Z","toolName":"read_secret","arguments":{"name":"DEPLOY_TOKEN"},"status":"success","result":{"metadata":{"token":"demo-secret"}}}
```

Secret-looking keys inside structured `result` values are redacted during import.

## Why This Exists

Agent ecosystems are moving fast: MCP servers, skills, coding agents, memory systems, evals, and local automation are becoming normal developer infrastructure. Teams need a small local tool that can inspect the practical risk surface before adopting or shipping agent workflows.

AgentOps Watchtower focuses on the useful middle ground:

- smaller than a full observability platform,
- broader than a single MCP inspector,
- safer than raw transcript sharing,
- easy to run in CI or locally.

See [docs/research.md](docs/research.md) for the v0.3 research notes and repository signal.

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

This is v1.2: local JSONL storage, deterministic evals, MCP descriptor scanning, MCP config inventory, AgentBOM export, MCP admission decisions, MCP preflight gate reports, stdio MCP runtime proxy enforcement, runtime attack graph analysis, signed tamper-evident evidence bundles, policy gates, GitHub Action support, tool-poisoning checks, MCP baseline drift detection, SARIF export, OpenTelemetry-style span export, and static reports. Planned next steps:

- SQLite storage.
- More agent transcript adapters.
- Streamable HTTP MCP proxy mode.
- Interactive approval prompts with signed approval evidence.
- Richer GitHub Action PR summaries.
- Browser-based local report viewer.

## License

MIT
