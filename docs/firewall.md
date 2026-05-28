# Capability Firewall

The Capability Firewall is Watchtower's policy-as-code layer for MCP tool calls.

It answers a runtime question:

> Should this agent be allowed to call this tool with these arguments right now?

## Why It Exists

Static MCP scans catch bad descriptors, but enterprises also need least-privilege control at invocation time. Current MCP gateway work is converging around deny-by-default policy, tool-call audit trails, and runtime enforcement. Watchtower keeps that workflow local-first: policy is a JSON file, simulation works from traces, and live enforcement can run through the existing stdio proxy.

The design is intentionally deterministic:

- no paid API;
- no cloud control plane;
- no model judgment in the allow/deny path;
- all arguments are redacted before evidence is written.

## Generate Policy

```bash
npx agentops-watchtower firewall init --descriptor examples/mcp/risky-tools.json
```

Output:

```text
.watchtower/firewall.json
```

The generated policy starts with `defaultDecision: "deny"` and creates one rule per descriptor:

- read-only local tools become `allow`;
- destructive or command-like tools become `deny`;
- open-world or unknown tools become `escalate`.

`escalate` means the call should require a human approval workflow before being forwarded. Watchtower records it as a finding in simulation today; signed approval receipts are a later layer.

## Simulate Policy

```bash
npx agentops-watchtower firewall simulate \
  --config .watchtower/firewall.json \
  --trace examples/traces/firewall-violation.jsonl \
  --fail-on high
```

Output:

```text
.watchtower/reports/firewall-report.json
```

The report records:

- every evaluated tool call;
- allow, deny, or escalation decision;
- matching rule id when available;
- redacted arguments;
- policy findings suitable for evidence bundles.

## Enforce During MCP Proxying

```bash
npx agentops-watchtower proxy-mcp \
  --config .mcp.json \
  --server github \
  --descriptor mcp-tools.json \
  --firewall .watchtower/firewall.json
```

To install that into an MCP client config without editing JSON by hand:

```bash
npx agentops-watchtower protect-mcp \
  --config .mcp.json \
  --server github \
  --descriptor mcp-tools.json \
  --firewall .watchtower/firewall.json
```

During live proxying, firewall decisions run before the runtime attack graph and default proxy policy checks. A deny or escalation decision blocks the JSON-RPC `tools/call` request and writes a proxy audit finding.

## Policy Shape

```json
{
  "schemaVersion": 1,
  "generatedAt": "2026-05-28T00:00:00.000Z",
  "defaultDecision": "deny",
  "rules": [
    {
      "id": "tool-list_projects-allow",
      "decision": "allow",
      "reason": "Project listing is read-only and stays local.",
      "match": {
        "toolName": "list_projects"
      }
    },
    {
      "id": "tool-shell_exec-deny-dangerous-substrings",
      "decision": "deny",
      "severity": "high",
      "reason": "Shell execution with destructive substrings is not allowed.",
      "match": {
        "toolName": "shell_exec"
      },
      "conditions": {
        "forbiddenSubstrings": ["rm -rf", "curl |", "powershell -enc"]
      }
    }
  ]
}
```

Rules support exact or regex matching for `serverName` and `toolName`. Conditions currently support forbidden substrings, path allow-list violations, and maximum string length triggers.

## Evidence Flow

`firewall simulate` output is included by `attest-mcp` when present. That means a review bundle can prove:

- the policy file used for review;
- which trace was replayed;
- which calls would be denied or escalated;
- whether the report changed after signing.

## Boundaries

- v1.4 policy is JSON, not Rego/OPA.
- Escalation is represented as a blocking finding, not an interactive prompt.
- Live enforcement is for local stdio MCP servers through `proxy-mcp`.
- Streamable HTTP/SSE proxying and signed approval receipts are planned later layers.

## Research Context

- Docker MCP Gateway emphasizes secure MCP infrastructure with gateway-based control: https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/
- Permit MCP Gateway documents least privilege, deny-by-default access, and complete audit trails: https://docs.permit.io/permit-mcp-gateway/
- The "Prompts Don't Protect" paper argues that architectural enforcement at tool discovery and invocation is necessary for reliable tool access control: https://arxiv.org/abs/2605.18414
- NVD CVE-2025-49596 shows how MCP tooling exposed stdio command launch risk when authentication was missing: https://nvd.nist.gov/vuln/detail/CVE-2025-49596
