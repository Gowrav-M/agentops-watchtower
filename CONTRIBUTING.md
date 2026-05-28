# Contributing

AgentOps Watchtower is a local-first security and observability toolkit for agent workflows. Contributions should strengthen that lane: deterministic analysis, MCP safety, runtime evidence, CI adoption, or high-quality docs.

## Development

```bash
npm install
npm run typecheck
npm test
npm run lint
npm run build
node dist/cli.js demo
```

Use Node.js 22 or newer.

## Good First Areas

- New trace import adapters for Codex, Claude Code, Cursor, OpenCode, Gemini CLI, and OpenHands.
- More MCP config discovery paths and safer config parsers.
- Policy presets for common MCP server classes.
- Report rendering improvements that keep output local and reproducible.
- Documentation examples that show real failure modes with fake secrets and fake tools.

## Design Rules

- Keep local-first behavior as the default.
- Do not add paid API or cloud dependencies to core commands.
- Prefer deterministic checks before model-based judgment.
- Redact secret-looking data before writing artifacts.
- Keep schemas explicit and runtime-validated.
- Add tests for new behavior.

## Pull Request Checklist

- [ ] `npm run typecheck`
- [ ] `npm test`
- [ ] `npm run lint`
- [ ] `npm run build`
- [ ] `node dist/cli.js demo`
- [ ] Docs updated when commands, artifacts, or behavior change.
