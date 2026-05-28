# Changelog

## 1.5.0 - 2026-05-28

- Added `setup` for one-command local onboarding with config, starter MCP scan, firewall policy, and slash-command templates.
- Added `check` to compose descriptor scanning, runtime attack graph analysis, optional firewall replay, reports, and SARIF from one command.
- Added `protect` as a friendly shortcut over `protect-mcp` while keeping the advanced command fully available.
- Added tracked slash-command examples and docs for `/watchtower-check`, `/watchtower-protect`, and `/watchtower-report`.
- Updated README quick start so simple commands come first without hiding CI and power-user workflows.

## 1.4.0 - 2026-05-28

- Added `firewall init` to generate default-deny Capability Firewall policies from MCP descriptors.
- Added `firewall simulate` to replay traces through local allow/deny/escalation policy and write firewall reports.
- Added `proxy-mcp --firewall` enforcement before runtime attack graph and default proxy checks.
- Added `protect-mcp --firewall` pass-through so protected client configs can install firewall policy without hand-editing JSON.
- Added firewall reports to demo output and evidence bundles.
- Added firewall examples, documentation, tests, and package keywords.

## 1.3.0 - 2026-05-28

- Added `protect-mcp` to generate protected MCP client config copies that route one server through `proxy-mcp`.
- Added `unprotect-mcp` rollback from protection manifests.
- Added in-place protection with backup configs to avoid recursive proxy launches.
- Added MCP protection docs, examples, tests, and package keywords.
- Added visual README positioning, industry research notes, contributing guide, and security policy.

## 1.2.0 - 2026-05-28

- Added `proxy-mcp` for stdio MCP runtime policy enforcement.
- Added runtime JSON-RPC blocking for destructive, command, and source-to-sink tool-call chains.
- Added MCP proxy audit artifacts and evidence-bundle inclusion.
- Added stdio proxy examples, docs, tests, and CI dry-run coverage.

## 1.1.0 - 2026-05-28

- Added the root `action.yml` composite GitHub Action for CI adoption.
- Added default CI report and evidence-bundle generation through `report` and `attest-mcp`.
- Added a reusable GitHub Actions example with SARIF upload.
- Added release polish docs: changelog and roadmap.

## 1.0.0 - 2026-05-28

- Added Ed25519 signed evidence bundles.
- Added signature verification through `verify-attestation --public-key`.
- Promoted the repository to v1.0 after AgentBOM, runtime attack graph, MCP gate, and signed evidence support.

## 0.9.0 - 2026-05-28

- Added Agent Bill of Materials export.
- Added CycloneDX-compatible AgentBOM output.

## 0.8.0 - 2026-05-28

- Added selected-server MCP preflight gate.

## 0.7.0 - 2026-05-27

- Added runtime attack graph analysis for tool-chain risk paths.

## 0.6.0 - 2026-05-27

- Added tamper-evident evidence bundles.
