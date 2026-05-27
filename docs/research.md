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
- Tool metadata can drift after review.
- Security teams already consume SARIF, but agent-specific risks rarely appear in that workflow.
- Observability teams need machine-readable spans, not only human dashboard screenshots.

Existing MCP scanners validate important pieces of this problem. Watchtower's differentiated lane is to combine the black box recorder, scanner, baseline drift detection, CI policy gate, SARIF, and OTel-style export in one local-first developer workflow.

## Gap Chosen For v0.3

The practical missing layer is not another dashboard or another agent runtime. It is local evidence:

- Was this MCP tool descriptor safe when reviewed?
- Did it change later?
- Can CI fail on the change?
- Can GitHub security views ingest the result?

v0.3 therefore adds MCP baselines, drift findings, and SARIF export.

## Source References

- OpenTelemetry GenAI/MCP semantic conventions: https://opentelemetry.io/docs/specs/semconv/gen-ai/mcp/
- OWASP MCP Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html
- OWASP MCP Top 10: https://owasp.org/www-project-mcp-top-10/
- GitHub SARIF upload docs: https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/uploading-a-sarif-file-to-github
