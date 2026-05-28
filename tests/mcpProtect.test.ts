import { describe, expect, it } from "vitest";
import { createMcpProtection, restoreMcpProtection } from "../src/core/mcpProtect.js";

describe("MCP config protection", () => {
  it("wraps one MCP server with the Watchtower proxy while preserving unrelated config", () => {
    const result = createMcpProtection(
      {
        mcpServers: {
          github: {
            command: "node",
            args: ["github-server.mjs"],
            env: { GITHUB_TOKEN: "$GITHUB_TOKEN" }
          },
          docs: {
            command: "node",
            args: ["docs-server.mjs"]
          }
        },
        ui: { theme: "dark" }
      },
      {
        generatedAt: "2026-05-28T00:00:00.000Z",
        serverName: "github",
        originalConfigPath: "D:/repo/.mcp.json",
        protectedConfigPath: "D:/repo/.watchtower/protected/.mcp.protected.json",
        packageSpec: "agentops-watchtower@1.3.0",
        descriptorPath: "D:/repo/mcp-tools.json",
        failOn: "high"
      }
    );

    expect(result.protectedConfig).toMatchObject({
      ui: { theme: "dark" },
      mcpServers: {
        docs: { command: "node", args: ["docs-server.mjs"] },
        github: {
          command: "npx",
          args: [
            "-y",
            "agentops-watchtower@1.3.0",
            "proxy-mcp",
            "--config",
            "D:/repo/.mcp.json",
            "--server",
            "github",
            "--descriptor",
            "D:/repo/mcp-tools.json",
            "--fail-on",
            "high"
          ]
        }
      }
    });
    expect(result.manifest).toMatchObject({
      schemaVersion: 1,
      mode: "copy",
      serverName: "github",
      originalServer: {
        command: "node",
        args: ["github-server.mjs"]
      }
    });
  });

  it("uses the backup config as proxy upstream for in-place protection", () => {
    const result = createMcpProtection(
      {
        mcpServers: {
          github: {
            command: "node",
            args: ["github-server.mjs"]
          }
        }
      },
      {
        generatedAt: "2026-05-28T00:00:00.000Z",
        serverName: "github",
        originalConfigPath: "D:/repo/.mcp.json",
        protectedConfigPath: "D:/repo/.mcp.json",
        backupConfigPath: "D:/repo/.watchtower/protected/.mcp.backup.json",
        packageSpec: "agentops-watchtower@1.3.0"
      }
    );

    expect(result.manifest.protectedServer).toEqual({
      command: "npx",
      args: [
        "-y",
        "agentops-watchtower@1.3.0",
        "proxy-mcp",
        "--config",
        "D:/repo/.watchtower/protected/.mcp.backup.json",
        "--server",
        "github"
      ]
    });
    expect(result.manifest.mode).toBe("in-place");
    expect(result.manifest.backupConfigPath).toBe("D:/repo/.watchtower/protected/.mcp.backup.json");
  });

  it("refuses to protect a server that is already wrapped", () => {
    expect(() =>
      createMcpProtection(
        {
          mcpServers: {
            github: {
              command: "npx",
              args: ["-y", "agentops-watchtower@1.3.0", "proxy-mcp", "--config", "backup.json", "--server", "github"]
            }
          }
        },
        {
          generatedAt: "2026-05-28T00:00:00.000Z",
          serverName: "github",
          originalConfigPath: "D:/repo/.mcp.json",
          protectedConfigPath: "D:/repo/.watchtower/protected/.mcp.protected.json",
          packageSpec: "agentops-watchtower@1.3.0"
        }
      )
    ).toThrow(/already protected/u);
  });

  it("restores the original server from a protection manifest", () => {
    const protectedResult = createMcpProtection(
      {
        mcpServers: {
          github: {
            command: "node",
            args: ["github-server.mjs"]
          }
        }
      },
      {
        generatedAt: "2026-05-28T00:00:00.000Z",
        serverName: "github",
        originalConfigPath: "D:/repo/.mcp.json",
        protectedConfigPath: "D:/repo/.mcp.json",
        backupConfigPath: "D:/repo/.watchtower/protected/.mcp.backup.json",
        packageSpec: "agentops-watchtower@1.3.0"
      }
    );

    const restored = restoreMcpProtection(protectedResult.protectedConfig, protectedResult.manifest);

    expect(restored).toEqual({
      mcpServers: {
        github: {
          command: "node",
          args: ["github-server.mjs"]
        }
      }
    });
  });

  it("refuses to restore over a server that is not currently protected", () => {
    const protectedResult = createMcpProtection(
      {
        mcpServers: {
          github: {
            command: "node",
            args: ["github-server.mjs"]
          }
        }
      },
      {
        generatedAt: "2026-05-28T00:00:00.000Z",
        serverName: "github",
        originalConfigPath: "D:/repo/.mcp.json",
        protectedConfigPath: "D:/repo/.mcp.json",
        backupConfigPath: "D:/repo/.watchtower/protected/.mcp.backup.json",
        packageSpec: "agentops-watchtower@1.3.0"
      }
    );

    expect(() =>
      restoreMcpProtection(
        {
          mcpServers: {
            github: {
              command: "node",
              args: ["different-server.mjs"]
            }
          }
        },
        protectedResult.manifest
      )
    ).toThrow(/not currently protected/u);
  });
});
