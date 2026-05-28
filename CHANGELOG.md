# Changelog

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
