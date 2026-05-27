import type { RiskFinding, Severity } from "./schemas.js";

export interface SarifLog {
  $schema: "https://json.schemastore.org/sarif-2.1.0.json";
  version: "2.1.0";
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: "AgentOps Watchtower";
      informationUri: string;
      rules: SarifRule[];
    };
  };
  invocations?: SarifInvocation[];
  results: SarifResult[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: {
    text: string;
  };
  fullDescription: {
    text: string;
  };
  help: {
    text: string;
  };
  properties: {
    tags: string[];
  };
}

interface SarifInvocation {
  commandLine: string;
  executionSuccessful: boolean;
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: "error" | "warning" | "note";
  message: {
    text: string;
  };
  locations?: SarifLocation[];
  partialFingerprints: {
    watchtowerFindingId: string;
  };
  properties: {
    severity: Severity;
    target?: string;
    evidence?: string[];
  };
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string;
    };
  };
}

export interface SarifExportOptions {
  sourceUri?: string;
  invocationCommandLine?: string;
}

const SEVERITY_TO_LEVEL: Record<Severity, SarifResult["level"]> = {
  info: "note",
  low: "warning",
  medium: "warning",
  high: "error",
  critical: "error"
};

export function exportSarif(findings: readonly RiskFinding[], options: SarifExportOptions = {}): SarifLog {
  const ruleIds = [...new Set(findings.map((finding) => finding.category))].sort();
  const rules = ruleIds.map((ruleId) => createRule(ruleId));
  const ruleIndex = new Map(rules.map((rule, index) => [rule.id, index]));

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "AgentOps Watchtower",
            informationUri: "https://github.com/Gowrav-M/agentops-watchtower",
            rules
          }
        },
        ...(options.invocationCommandLine === undefined
          ? {}
          : {
              invocations: [
                {
                  commandLine: options.invocationCommandLine,
                  executionSuccessful: true
                }
              ]
            }),
        results: findings.map((finding) => createResult(finding, ruleIndex.get(finding.category) ?? 0, options.sourceUri))
      }
    ]
  };
}

function createRule(ruleId: string): SarifRule {
  return {
    id: ruleId,
    name: ruleId,
    shortDescription: {
      text: ruleId
    },
    fullDescription: {
      text: `AgentOps Watchtower finding category: ${ruleId}.`
    },
    help: {
      text: "Review the finding recommendation and inspect the MCP descriptor or agent trace that produced it."
    },
    properties: {
      tags: ["agentops-watchtower", ...ruleId.split(".")]
    }
  };
}

function createResult(finding: RiskFinding, ruleIndex: number, sourceUri: string | undefined): SarifResult {
  return {
    ruleId: finding.category,
    ruleIndex,
    level: SEVERITY_TO_LEVEL[finding.severity],
    message: {
      text: `${finding.title}. ${finding.description} Recommendation: ${finding.recommendation}`
    },
    ...(sourceUri === undefined
      ? {}
      : {
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: sourceUri
                }
              }
            }
          ]
        }),
    partialFingerprints: {
      watchtowerFindingId: finding.id
    },
    properties: {
      severity: finding.severity,
      ...(finding.target === undefined ? {} : { target: finding.target }),
      ...(finding.evidence === undefined ? {} : { evidence: finding.evidence })
    }
  };
}
