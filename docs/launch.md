# Launch And Distribution

Watchtower already has the industrial substance: MCP scanning, config inventory, baselines, runtime attack graphs, Capability Firewall, protected MCP configs, SARIF, OTel-style spans, AgentBOM, CycloneDX, and signed evidence.

The star-growth gap is presentation and distribution. Trending developer tools usually win because a developer understands the value in one screen, runs one command, sees visual proof, and knows where it plugs into their current workflow.

## Positioning

Use this one-line description:

> Black box recorder and firewall for AI coding agents.

Use this longer description:

> AgentOps Watchtower shows what an AI coding agent did, which MCP tools were risky, which runtime tool chains looked unsafe, and what evidence can be attached before a workflow is trusted.

## First-Run Promise

```bash
npx agentops-watchtower setup
npx agentops-watchtower check
npx agentops-watchtower protect --config .mcp.json --server github
```

The first run should produce visible artifacts:

- `.watchtower/reports/watchtower-report.html`
- `.watchtower/reports/attack-graph.json`
- `.watchtower/reports/firewall-report.json`
- `.watchtower/reports/watchtower.sarif`
- `.watchtower/firewall.json`
- `.watchtower/slash-commands/`

## Launch Checklist

- Add `docs/assets/watchtower-social-card.svg` as the GitHub social preview image in repository settings.
- Publish the GitHub Action from `action.yml` after creating a tagged release.
- Create a short demo GIF from `npx agentops-watchtower setup`, `check`, and `protect`.
- Pin the generated report preview in the README first viewport.
- Add GitHub topics: `agentops`, `mcp`, `ai-agents`, `mcp-security`, `codex`, `claude-code`, `cursor`, `opencode`, `agent-observability`, `runtime-security`, `sarif`, `opentelemetry`.
- Create a `v1.5.0` release with the simple UX, slash commands, and visual assets as the headline.
- Submit the repo to curated lists for MCP, Claude Code, AI agents, and security tools.

## Launch Copy

Short:

> I built AgentOps Watchtower: a local-first black box recorder and firewall for AI coding agents. It scans MCP tools, detects risky runtime chains, protects MCP configs, and writes reports, SARIF, OTel-style spans, AgentBOM, and signed evidence.

Developer-focused:

> AI coding agents can read files, call MCP tools, run shells, post to external services, and touch secrets. Watchtower gives you local forensic evidence: what happened, what was risky, what should be blocked, and what proof to attach in a PR.

Security-focused:

> Watchtower is not another agent framework. It is a local safety layer around Codex, Claude Code, Cursor, OpenCode, Gemini CLI, and MCP servers: descriptor scan, config inventory, runtime attack graph, Capability Firewall, protected MCP config, and tamper-evident evidence bundle.

## Where To Share

- GitHub release notes.
- Hacker News Show HN.
- Reddit communities around MCP, Claude Code, AI agents, DevOps, and cybersecurity.
- LinkedIn post aimed at platform engineering and AI infrastructure teams.
- X thread with the report preview image and the three commands.
- Dev.to or Medium write-up: "I built a black box recorder for AI coding agents."

## What To Measure

- Stars after 24 hours, 7 days, and 30 days.
- npm downloads.
- GitHub Action usage.
- README click-through to docs.
- Issues opened by real users.
- External mentions or list inclusions.

## Next Product Bets

Do these only after the launch surface is clear:

1. Real terminal GIF in README.
2. `watchtower doctor --json` for automation.
3. Optional local web report viewer.
4. Native slash-command installers for Claude Code, Codex, Cursor, and Gemini CLI.
5. MCP proxy hardening and policy packs for common servers.
