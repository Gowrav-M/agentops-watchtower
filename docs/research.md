# Research Notes

Generated on 2026-05-27 from public repository metadata and current security/observability guidance.

## Repository Signal

High-star AI infrastructure repositories cluster around agent execution, MCP, observability, and developer tooling:

| Repository | Stars observed | Signal |
| --- | ---: | --- |
| `anthropics/claude-code` | 126,960 | Terminal coding agents are mainstream developer workflow. |
| `google-gemini/gemini-cli` | 104,654 | Local CLI agents have broad demand. |
| `modelcontextprotocol/servers` | 86,328 | MCP server ecosystems are a major distribution surface. |
| `openai/codex` | 86,264 | Coding-agent black-box workflows need local operational tooling. |
| `ChromeDevTools/chrome-devtools-mcp` | 41,960 | MCP tools that expose powerful browser/runtime capabilities are popular. |
| `microsoft/playwright-mcp` | 33,096 | Tool-using agents need safer inspection and automation layers. |
| `langfuse/langfuse` | 28,060 | LLM observability/evals are a strong infrastructure category. |
| `PrefectHQ/fastmcp` | 25,343 | Developer-friendly MCP builders are growing quickly. |
| `modelcontextprotocol/inspector` | 9,891 | Manual MCP inspection exists, but CI-grade safety/reporting is still a gap. |

## Standards Signal

- OpenTelemetry now has GenAI and MCP semantic conventions. Watchtower maps agent/tool runs to GenAI/MCP span JSON so teams can migrate toward collectors later.
- OWASP MCP guidance calls out tool poisoning, data exfiltration through legitimate channels, confused deputy behavior, and over-scoped tokens.
- GitHub Code Scanning accepts third-party SARIF, which lets security findings appear in the same workflow as other static analysis tools.

## Industrial Pain

Enterprise agent work is blocked less by model access and more by control gaps:

- Agents use tools with real permissions, but teams often lack a local record of what happened.
- MCP descriptors are prompt surfaces, not just API metadata.
- MCP client configs are launch surfaces: they can run shells, package managers, local scripts, or remote URLs before any tool call happens.
- Tool metadata can drift after review.
- Security teams already consume SARIF, but agent-specific risks rarely appear in that workflow.
- Observability teams need machine-readable spans, not only human dashboard screenshots.

Existing MCP scanners validate important pieces of this problem. Watchtower's differentiated lane is to combine the black box recorder, config inventory, scanner, baseline drift detection, CI policy gate, SARIF, and OTel-style export in one local-first developer workflow.

## Gap Chosen For v0.3

The practical missing layer is not another dashboard or another agent runtime. It is local evidence:

- Was this MCP tool descriptor safe when reviewed?
- Did it change later?
- Can CI fail on the change?
- Can GitHub security views ingest the result?

v0.3 added MCP baselines, drift findings, and SARIF export.

v0.4 extends the same evidence model to installed MCP client configuration. It inventories Codex, Claude Code, Claude Desktop, Cursor, VS Code, and Gemini CLI config locations and flags dangerous launch paths before the server starts.

v0.5 adds local admission control: config inventory, descriptor scan, and baseline drift are combined into a single `allow`, `review`, or `deny` decision that CI and security reviewers can consume.

v0.6 adds tamper-evident evidence bundles. This addresses the audit and non-repudiation gap: teams can prove which artifacts were reviewed, what admission decision was made, and whether the evidence changed later.

v0.7 adds runtime attack graph analysis. This addresses a deeper gap surfaced by OWASP and Microsoft guidance: even if tools pass static review, an agent can combine a source and sink into a dangerous chain at runtime. Watchtower now flags source-to-sink paths, prompt-injected tool results, and blocked-action bypass patterns from local traces.

v0.8 adds a selected-server MCP preflight gate. This starts the enforcement path without overbuilding a protocol proxy: one configured server is inventoried, checked against descriptor and baseline evidence, and turned into a blocked or dry-run launch plan.

v0.9 adds AgentBOM export. Current guidance around shadow AI, OpenSSF AI supply-chain security, and CycloneDX AI/ML-BOM points toward machine-readable inventory as a governance primitive. Watchtower now emits a local Agent Bill of Materials plus a CycloneDX-compatible component view for MCP configs, servers, tools, fingerprints, and findings.

v1.0 adds signed evidence bundles. This closes the local audit loop: teams can prove which artifacts were reviewed, detect later mutation, and verify reviewer/key identity with Ed25519 signatures.

v1.1 adds a packaged GitHub Action. This turns Watchtower from a local-only CLI into a reusable CI adoption path with scan, report, AgentBOM, admission, attack graph, and evidence output.

v1.2 adds the stdio MCP runtime proxy. This moves Watchtower from detective control to preventive control for local MCP servers by blocking unsafe `tools/call` requests before the upstream server executes them.

v1.3 adds MCP protect mode. This closes the adoption gap for the proxy: developers can generate a protected MCP client config or safely edit in place with a backup and rollback manifest.

v1.4 adds the Capability Firewall. This responds to the next industrial gap: least-privilege enforcement cannot live only in prompts or static scanner output. Teams need a local policy file that can be generated from descriptors, simulated from traces, attached to evidence bundles, and enforced before stdio MCP tool calls execute. The implementation stays local-first and deterministic while matching the market direction toward gateway policy, deny-by-default control, and auditable invocation decisions.

## Positioning Update - 2026-05-28

The README and docs were updated to reflect a stronger public positioning:

- "black box recorder + MCP safety firewall + evidence pack" is clearer than a long feature list;
- top repositories in the category teach that fast adoption comes from visible quickstarts, strong examples, diagrams, and concrete workflows;
- README structure now follows GitHub's recommended reader path: what it does, why it is useful, how to start, where to learn more, and how to contribute;
- standards links are surfaced early so recruiters and security-minded developers understand the industrial relevance immediately.

## v1.4 Web Signal - 2026-05-28

- Docker MCP Gateway positions the gateway as secure infrastructure for agentic AI and emphasizes controlled MCP server execution.
- Permit MCP Gateway explicitly markets identity-aware access control, least privilege by default, deny-by-default policy, and complete audit trails.
- The 2026 "Prompts Don't Protect" paper argues for architectural enforcement at tool discovery and tool invocation because prompt-only restrictions leave residual risk.
- VIPER-MCP research highlights privileged MCP operations such as shell execution, network access, and file-system manipulation as direct paths to sensitive sinks.
- CVE-2025-49596 in MCP Inspector shows that unauthenticated stdio command launch paths can become critical developer-machine exposure.

## Source References

- OpenTelemetry GenAI/MCP semantic conventions: https://opentelemetry.io/docs/specs/semconv/gen-ai/mcp/
- OWASP MCP Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html
- OWASP MCP Top 10: https://owasp.org/www-project-mcp-top-10/
- GitHub SARIF upload docs: https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/uploading-a-sarif-file-to-github
- Microsoft indirect prompt injection defense guidance: https://learn.microsoft.com/en-us/security/zero-trust/sfi/defend-indirect-prompt-injection
- MCP security best practices: https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices
- GitHub README guidance: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes
- CycloneDX specification overview: https://cyclonedx.org/specification/overview/
- CycloneDX AI/ML-BOM capability: https://cyclonedx.org/capabilities/mlbom/
- Docker MCP Gateway: https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/
- Permit MCP Gateway: https://docs.permit.io/permit-mcp-gateway/
- Prompts Don't Protect: https://arxiv.org/abs/2605.18414
- VIPER-MCP: https://arxiv.org/abs/2605.21392
- NVD CVE-2025-49596: https://nvd.nist.gov/vuln/detail/CVE-2025-49596
