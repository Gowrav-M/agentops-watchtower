# Evidence Bundles

Watchtower can create a tamper-evident local evidence bundle after scans, inventory, baseline checks, reports, or admission decisions.

```bash
npx agentops-watchtower admit-mcp --descriptor mcp-tools.json --config .mcp.json --sarif
npx agentops-watchtower attest-mcp --subject production-github-mcp --private-key private.pem --key-id security-reviewer
npx agentops-watchtower verify-attestation --public-key public.pem
```

Output:

```text
.watchtower/reports/evidence-bundle.json
```

## What It Contains

The bundle records:

- subject
- admission decision, when available
- artifact names and relative paths
- artifact byte sizes
- SHA-256 hash for every artifact
- bundle-level integrity hash
- optional Ed25519 signature metadata and signature

Artifacts can include:

- `mcp-admission.json`
- `mcp-gate.json`
- `mcp-inventory.json`
- `agent-bom.json`
- `agent-bom.cdx.json`
- `mcp-scan.json`
- `mcp-baseline-diff.json`
- `attack-graph.json`
- `watchtower.sarif`
- `watchtower-report.json`

## Why It Matters

Security teams need non-repudiation: proof of what was reviewed, which decision was made, and whether the evidence was modified later. The bundle is local-first and dependency-free, but gives teams a stable artifact to attach to PRs, tickets, audit records, and release approvals.

`verify-attestation` recomputes the bundle integrity hash and every artifact hash. If a report changes after approval, verification fails. With `--public-key`, it also verifies the Ed25519 signature over the bundle metadata, artifact hashes, and integrity hash.

## Signing Keys

Watchtower accepts standard PEM Ed25519 keys:

- private key: PKCS#8 PEM
- public key: SPKI PEM

Generate and manage keys with your existing security tooling. Keep private keys out of repositories and CI logs.
