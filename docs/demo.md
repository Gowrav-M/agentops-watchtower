# Demo Proof

This repository includes a short proof demo with audio:

- [Watch the MP4](assets/agentops-watchtower-repository-pitch.mp4)
- [Open the poster image](assets/agentops-watchtower-pitch-poster.png)

The demo was generated from a clean local proof workspace using the public npm package:

```bash
npx -y agentops-watchtower@latest --version
npx -y agentops-watchtower@latest demo
npx -y agentops-watchtower@latest setup --descriptor inputs/mcp/risky-tools.json
npx -y agentops-watchtower@latest doctor
npx -y agentops-watchtower@latest check \
  --descriptor inputs/mcp/risky-tools.json \
  --config inputs/mcp/sample-client-config.json \
  --trace inputs/traces/source-to-sink.jsonl \
  --firewall .watchtower/firewall.json \
  --sarif \
  --fail-on critical
npx -y agentops-watchtower@latest check \
  --descriptor inputs/mcp/safe-tools.json \
  --config inputs/mcp/safe-client-config.json \
  --trace inputs/traces/codex-session.jsonl \
  --firewall .watchtower/firewall.json \
  --sarif \
  --fail-on critical
npx -y agentops-watchtower@latest protect \
  --config inputs/mcp/stdio-client-config.json \
  --server local-echo \
  --firewall .watchtower/firewall.json
```

Expected proof points:

| Proof point | Expected result |
| --- | --- |
| Public install | `npx agentops-watchtower@latest --version` prints the published version. |
| Demo run | `demo` creates local `.watchtower/reports/*` artifacts. |
| Risk gate | The source-to-sink trace exits non-zero at `--fail-on critical`. |
| Safe report | The safe trace writes Markdown, HTML, JSON, and SARIF reports. |
| MCP protection | `protect` writes a protected MCP config and rollback manifest. |

The pitch video is intentionally not a product dashboard. Watchtower remains a CLI-first, local-first tool for evidence and safety around agent workflows.
