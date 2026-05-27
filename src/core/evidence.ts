import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { relative, resolve } from "node:path";
import type { AdmissionDecision, AdmissionReport } from "./admission.js";
import type { JsonValue } from "./schemas.js";

export interface EvidenceArtifactInput {
  name: string;
  path: string;
}

export interface EvidenceArtifact {
  name: string;
  path: string;
  sha256: string;
  bytes: number;
}

export interface EvidenceBundle {
  schemaVersion: 1;
  generatedAt: string;
  subject?: string;
  admissionDecision?: AdmissionDecision;
  artifacts: EvidenceArtifact[];
  integrityHash: string;
}

export interface CreateEvidenceBundleInput {
  cwd: string;
  generatedAt?: string;
  subject?: string;
  admissionDecision?: AdmissionDecision;
  artifacts: EvidenceArtifactInput[];
}

export interface EvidenceVerification {
  ok: boolean;
  failures: string[];
}

export async function createEvidenceBundle(input: CreateEvidenceBundleInput): Promise<EvidenceBundle> {
  const artifacts = await Promise.all(input.artifacts.map((artifact) => hashArtifact(input.cwd, artifact)));
  const unsignedBundle = {
    schemaVersion: 1 as const,
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    ...(input.subject === undefined ? {} : { subject: input.subject }),
    ...(input.admissionDecision === undefined ? {} : { admissionDecision: input.admissionDecision }),
    artifacts: artifacts.sort((left, right) => left.name.localeCompare(right.name) || left.path.localeCompare(right.path))
  };

  return {
    ...unsignedBundle,
    integrityHash: sha256(stableStringify(unsignedBundle as unknown as JsonValue))
  };
}

export async function verifyEvidenceBundle(bundle: EvidenceBundle, cwd: string): Promise<EvidenceVerification> {
  const failures: string[] = [];
  const unsignedBundle: Omit<EvidenceBundle, "integrityHash"> = {
    schemaVersion: bundle.schemaVersion,
    generatedAt: bundle.generatedAt,
    ...(bundle.subject === undefined ? {} : { subject: bundle.subject }),
    ...(bundle.admissionDecision === undefined ? {} : { admissionDecision: bundle.admissionDecision }),
    artifacts: bundle.artifacts
  };
  const expectedIntegrity = sha256(stableStringify(unsignedBundle as unknown as JsonValue));
  if (expectedIntegrity !== bundle.integrityHash) {
    failures.push("integrity hash mismatch");
  }

  for (const artifact of bundle.artifacts) {
    const path = resolve(cwd, artifact.path);
    try {
      const content = await readFile(path);
      const actualHash = sha256(content);
      if (actualHash !== artifact.sha256) {
        failures.push(`${artifact.name}: hash mismatch`);
      }
      if (content.byteLength !== artifact.bytes) {
        failures.push(`${artifact.name}: byte length mismatch`);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "unknown error";
      failures.push(`${artifact.name}: could not read artifact: ${message}`);
    }
  }

  return {
    ok: failures.length === 0,
    failures
  };
}

export async function readAdmissionDecision(path: string): Promise<AdmissionDecision | undefined> {
  try {
    const raw = JSON.parse(await readFile(path, "utf8")) as Partial<AdmissionReport>;
    return raw.decision;
  } catch {
    return undefined;
  }
}

async function hashArtifact(cwd: string, artifact: EvidenceArtifactInput): Promise<EvidenceArtifact> {
  const content = await readFile(artifact.path);
  return {
    name: artifact.name,
    path: relative(cwd, artifact.path).replaceAll("\\", "/"),
    sha256: sha256(content),
    bytes: content.byteLength
  };
}

function sha256(value: Buffer | string): string {
  return createHash("sha256").update(value).digest("hex");
}

function stableStringify(value: JsonValue): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }

  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key] ?? null)}`)
      .join(",")}}`;
  }

  return JSON.stringify(value);
}
