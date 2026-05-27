# Threat Model

AgentOps Watchtower treats agent traces and MCP descriptors as untrusted local input.

## Assets

- Local agent transcripts.
- Tool call arguments.
- MCP server descriptors.
- Generated reports.
- Developer workstation files under `.watchtower/`.

## Risks Covered in v0.1

- Secret-looking input fields in MCP schemas.
- Secret-looking tool call arguments.
- Destructive MCP tools with missing or misleading annotations.
- Tools that can affect external systems.
- Missing output schemas that make tool results harder to use safely.
- Weak tool descriptions that hide side effects.
- Failed agent steps and risky tool-call names in imported traces.

## Deliberate Limits

- The scanner does not execute MCP servers.
- The scanner does not prove actual runtime side effects.
- Reports are local static files and should still be reviewed before sharing.
- v0.1 does not connect to external LLMs or cloud observability backends.

## Safe Defaults

- No network calls.
- No cloud sync.
- No credential collection.
- Redaction runs during trace import.
- Generated `.watchtower/` data is ignored by Git by default.
