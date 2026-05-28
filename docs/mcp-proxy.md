# MCP Runtime Proxy

`proxy-mcp` runs a local stdio MCP server behind Watchtower policy enforcement. It is the first runtime prevention layer:

> Can Watchtower block unsafe MCP tool calls before the server executes them?

## Usage

```bash
npx agentops-watchtower proxy-mcp \
  --config .mcp.json \
  --server github \
  --descriptor mcp-tools.json
```

Dry-run mode performs the same preflight gate and writes an empty audit artifact without launching the server:

```bash
npx agentops-watchtower proxy-mcp \
  --config examples/mcp/stdio-client-config.json \
  --server local-echo \
  --dry-run
```

Output:

```text
.watchtower/reports/mcp-gate.json
.watchtower/reports/mcp-proxy-audit.json
```

## What It Blocks

The v1.2 proxy intercepts stdio JSON-RPC messages and evaluates `tools/call` before forwarding them. It can block:

- direct destructive or command-execution tool calls when `allowDestructiveTools` is false;
- open-world tool calls when `allowOpenWorldTools` is false;
- runtime attack chains detected by Watchtower, such as `read_secret -> send_email`;
- prompt-injected untrusted content followed by shell, destructive, or external sink tools.

Blocked requests receive a local JSON-RPC error:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "error": {
    "code": -32080,
    "message": "Blocked by AgentOps Watchtower policy"
  }
}
```

## Audit

The audit file records redacted tool arguments, allow/block decisions, response status, result summaries, and findings. It is included in evidence bundles when present.

## Boundaries

v1.2 supports local stdio MCP servers. It does not yet proxy Streamable HTTP/SSE servers, prompt for interactive approvals, or inject credentials from config env blocks. Those are deliberate next layers after deterministic stdio enforcement is solid.
