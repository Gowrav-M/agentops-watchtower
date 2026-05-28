# Architecture

AgentOps Watchtower is a local-first CLI. The core design keeps parsing, scanning, evaluation, and reporting independent from the command layer so the same engine can later power a GitHub Action, MCP server, or local dashboard.

```mermaid
flowchart LR
  CLI["CLI commands"] --> Importer["Trace importer"]
  CLI --> Scanner["MCP scanner"]
  CLI --> Inventory["MCP config inventory"]
  CLI --> AgentBOM["AgentBOM export"]
  CLI --> Baseline["MCP baseline diff"]
  CLI --> Admission["MCP admission gate"]
  CLI --> Gate["MCP preflight gate"]
  CLI --> Firewall["Capability Firewall"]
  CLI --> Proxy["MCP runtime proxy"]
  CLI --> Protect["MCP config protection"]
  CLI --> AttackGraph["Runtime attack graph"]
  CLI --> Evidence["Evidence bundle"]
  Importer --> Runs["Local JSONL runs"]
  Scanner --> Findings["Risk findings"]
  Inventory --> Findings
  Inventory --> AgentBOM
  Scanner --> AgentBOM
  Baseline --> Findings
  Findings --> Admission
  Findings --> Gate
  Scanner --> Firewall
  Protect --> Proxy
  Gate --> Proxy
  Firewall --> Proxy
  Firewall --> Evidence
  Proxy --> AttackGraph
  Proxy --> Evidence
  Admission --> Evidence
  Gate --> Evidence
  Runs --> Evals["Deterministic evals"]
  Runs --> AttackGraph
  AttackGraph --> Findings
  Findings --> Report["Report builder"]
  Evals --> Report
  Report --> Markdown["Markdown"]
  Report --> HTML["HTML"]
  Report --> JSON["JSON"]
  Runs --> OTel["OTel-style spans"]
  Findings --> SARIF["SARIF"]
  Scanner --> Policy["Policy gate"]
  Baseline --> Policy
  Report --> Policy
```

## Principles

- Local-first by default.
- Redact secrets before writing normalized traces.
- Keep schemas explicit and runtime-validated.
- Prefer deterministic checks before model-based judgment.
- Make reports reproducible and easy to attach to PRs or security reviews.

## Storage

Watchtower stores normalized runs in `.watchtower/runs/runs.jsonl`. Each line is one validated `AgentRun`.

Approved MCP fingerprints are stored in `.watchtower/baselines/mcp-tools.json`. Capability Firewall policy is stored in `.watchtower/firewall.json`. Protected MCP config copies, backups, and rollback manifests are stored in `.watchtower/protected/`. Reports, AgentBOM artifacts, MCP gate decisions, firewall simulation reports, proxy audit logs, runtime attack graphs, OTel-style spans, SARIF, and scan outputs are written under `.watchtower/reports/`.

## Main Modules

- `src/core/schemas.ts`: Zod contracts for runs, steps, tool calls, MCP descriptors, findings, eval results, and reports.
- `src/core/importer.ts`: JSONL and Markdown transcript ingestion.
- `src/core/admission.ts`: allow/review/deny MCP admission reports.
- `src/core/evidence.ts`: tamper-evident evidence bundles and verification.
- `src/core/agentBom.ts`: Agent Bill of Materials and CycloneDX-compatible export.
- `src/core/mcpGate.ts`: selected-server preflight gate and launch-plan reports.
- `src/core/firewall.ts`: least-privilege MCP Capability Firewall config generation, invocation decisions, and trace simulation reports.
- `src/core/mcpProtect.ts`: MCP client config wrapping and rollback manifest creation.
- `src/core/mcpProxy.ts`: stdio JSON-RPC MCP proxy enforcement and audit records.
- `src/core/attackGraph.ts`: runtime tool-chain classification, graph edges, and attack-path findings.
- `src/core/mcpScanner.ts`: MCP descriptor risk checks and tool-poisoning metadata scan.
- `src/core/mcpInventory.ts`: local MCP client config discovery and launch-risk analysis.
- `src/core/mcpBaseline.ts`: deterministic MCP tool fingerprint baselines and drift findings.
- `src/core/evaluator.ts`: deterministic trace evals.
- `src/core/policy.ts`: config loading and fail-on severity gates.
- `src/core/otelExporter.ts`: GenAI/MCP OpenTelemetry-style span export.
- `src/core/sarifExporter.ts`: SARIF 2.1.0 export for GitHub Code Scanning.
- `src/core/reportRenderer.ts`: Markdown and HTML rendering.
- `src/cli.ts`: command orchestration.
