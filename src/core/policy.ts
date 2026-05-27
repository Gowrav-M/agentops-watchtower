import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { RiskFinding, Severity } from "./schemas.js";
import { SeveritySchema } from "./schemas.js";
import { fileExists } from "./files.js";

const PolicySchema = z
  .object({
    failOn: SeveritySchema.optional(),
    requireOutputSchema: z.boolean().optional(),
    allowDestructiveTools: z.boolean().optional(),
    allowOpenWorldTools: z.boolean().optional(),
    detectToolPoisoning: z.boolean().optional()
  })
  .strict();

export const WatchtowerConfigSchema = z
  .object({
    schemaVersion: z.literal(1),
    storage: z.literal("local-jsonl"),
    runsFile: z.string().optional(),
    reportsDir: z.string().optional(),
    redaction: z.enum(["enabled", "disabled"]).optional(),
    policy: PolicySchema.optional()
  })
  .strict();

interface PolicyConfig {
  failOn: Severity;
  requireOutputSchema: boolean;
  allowDestructiveTools: boolean;
  allowOpenWorldTools: boolean;
  detectToolPoisoning: boolean;
}
type WatchtowerConfigInput = z.infer<typeof WatchtowerConfigSchema>;

export type WatchtowerConfig = Omit<WatchtowerConfigInput, "policy"> & {
  policy: PolicyConfig;
};

const DEFAULT_POLICY: PolicyConfig = {
  failOn: "critical",
  requireOutputSchema: true,
  allowDestructiveTools: false,
  allowOpenWorldTools: true,
  detectToolPoisoning: true
};

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

export async function loadWatchtowerConfig(cwd: string): Promise<WatchtowerConfig> {
  const candidates = [join(cwd, "watchtower.config.json"), join(cwd, ".watchtower", "config.json")];

  for (const candidate of candidates) {
    if (!(await fileExists(candidate))) {
      continue;
    }

    const raw = JSON.parse(await readFile(candidate, "utf8")) as unknown;
    const parsed = WatchtowerConfigSchema.parse(raw);
    return withPolicyDefaults(parsed);
  }

  return withPolicyDefaults({
    schemaVersion: 1,
    storage: "local-jsonl"
  });
}

export function shouldFailForFindings(findings: readonly RiskFinding[], failOn: Severity): boolean {
  const threshold = SEVERITY_RANK[failOn];
  return findings.some((finding) => SEVERITY_RANK[finding.severity] >= threshold);
}

export function summarizePolicyFailure(findings: readonly RiskFinding[], failOn: Severity): string {
  const failing = findings.filter((finding) => SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[failOn]);
  return `Policy threshold failed: ${failing.length} finding${failing.length === 1 ? "" : "s"} at ${failOn} or above.`;
}

function withPolicyDefaults(config: z.infer<typeof WatchtowerConfigSchema>): WatchtowerConfig {
  const policy = config.policy ?? {};
  return {
    ...config,
    policy: {
      failOn: policy.failOn ?? DEFAULT_POLICY.failOn,
      requireOutputSchema: policy.requireOutputSchema ?? DEFAULT_POLICY.requireOutputSchema,
      allowDestructiveTools: policy.allowDestructiveTools ?? DEFAULT_POLICY.allowDestructiveTools,
      allowOpenWorldTools: policy.allowOpenWorldTools ?? DEFAULT_POLICY.allowOpenWorldTools,
      detectToolPoisoning: policy.detectToolPoisoning ?? DEFAULT_POLICY.detectToolPoisoning
    }
  };
}
