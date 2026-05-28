# Runtime Attack Graph

`analyze-run` turns imported agent traces into a deterministic runtime graph. It is a local forensic layer for one question:

> Did the agent combine otherwise normal tool calls into a risky chain?

## Usage

```bash
npx agentops-watchtower analyze-run --trace examples/traces/source-to-sink.jsonl --sarif --fail-on high
```

Output:

```text
.watchtower/reports/attack-graph.json
.watchtower/reports/watchtower.sarif
```

Reports can include the same runtime findings:

```bash
npx agentops-watchtower report --trace examples/traces/source-to-sink.jsonl --analyze
```

## What It Models

The analyzer classifies each tool call as one of:

- `source`: secret-like, repository, or untrusted external content.
- `sink`: external, command-execution, or destructive action.
- `transform`: local processing or summarization.
- `approval`: consent or authorization step.
- `blocker`: a blocked tool call.

It then creates edges and findings for risky sequences:

- `runtime.secret_to_external_sink`
- `runtime.untrusted_to_privileged_sink`
- `runtime.repo_to_external_sink`
- `runtime.blocked_action_bypass`
- `runtime.prompt_injection`
- `runtime.sensitive_argument_to_sink`

## Trace Fields

Existing trace files stay valid. v0.7 adds optional fields to `tool_call` records:

```json
{
  "resultText": "plain tool output text",
  "result": {
    "structured": "tool output"
  }
}
```

`resultSummary`, `resultText`, and string values inside `result` are scanned for prompt-injection-like instructions. Secret-looking keys in structured `result` values are redacted during import.

## Boundaries

This is runtime risk-path inference, not a full taint-tracking VM. Without explicit provenance from an agent runtime, Watchtower infers paths from ordered tool calls, tool names, arguments, status, MCP descriptor hints, and optional config context.

For prevention, use `proxy-mcp`. The proxy applies the same runtime chain analysis before forwarding stdio MCP `tools/call` requests.
