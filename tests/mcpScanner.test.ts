import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scanMcpDescriptorFile } from "../src/core/mcpScanner.js";

const fixturePath = join(import.meta.dirname, "fixtures", "mcp-tools.json");

describe("mcp scanner", () => {
  it("flags destructive tools whose annotations understate risk", async () => {
    const result = await scanMcpDescriptorFile(fixturePath);

    expect(result.tools).toHaveLength(3);
    expect(
      result.findings.some(
        (finding) =>
          finding.severity === "critical" &&
          finding.category === "mcp.destructive_hint" &&
          finding.title.includes("delete_repository")
      )
    ).toBe(true);
  });

  it("warns on missing outputSchema and sensitive input fields", async () => {
    const result = await scanMcpDescriptorFile(fixturePath);

    expect(
      result.findings.some(
        (finding) => finding.category === "mcp.output_schema" && finding.title.includes("send_email")
      )
    ).toBe(true);
    expect(
      result.findings.some(
        (finding) => finding.category === "mcp.sensitive_input" && finding.title.includes("apiKey")
      )
    ).toBe(true);
  });

  it("returns a useful parse error for malformed descriptor files", async () => {
    const malformed = join(import.meta.dirname, "fixtures", "malformed.json");
    await expect(scanMcpDescriptorFile(malformed)).rejects.toThrow(/Could not parse MCP descriptor JSON/u);
  });
});
