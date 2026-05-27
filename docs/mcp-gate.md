# MCP Preflight Gate

`gate-mcp` is a local preflight control for one configured MCP server. It answers:

> Would Watchtower allow this server to launch with the current config, descriptor, and baseline evidence?

## Usage

```bash
npx agentops-watchtower gate-mcp \
  --config .mcp.json \
  --server github \
  --descriptor mcp-tools.json \
  --baseline .watchtower/baselines/mcp-tools.json \
  --sarif
```

Output:

```text
.watchtower/reports/mcp-gate.json
```

## Decisions

The gate reuses the admission model:

- `allow`: no material findings.
- `review`: medium or high findings require human review.
- `deny`: critical findings block use.

The launch plan is narrower:

- `dry-run`: the gate passed, or `--allow-review` was supplied after human approval.
- `blocked`: the server is denied, or review is required and `--allow-review` was not supplied.

`gate-mcp` exits non-zero when the policy threshold fails or when the launch plan is blocked.

## How It Builds Evidence

The command:

- inventories the provided MCP config files;
- selects one server by `--server` name or inventory id;
- filters config findings to that selected server;
- optionally scans a descriptor;
- optionally compares against an approved baseline;
- writes SARIF when requested.

v0.8 records the approved launch plan but does not execute arbitrary server commands. That keeps the feature useful in CI and local reviews without becoming a process supervisor or MCP protocol proxy too early.
