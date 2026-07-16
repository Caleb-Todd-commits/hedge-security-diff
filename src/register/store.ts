import { resolve } from "node:path";
import {
  ThreatRegisterSchema,
  VerificationEvidenceSchema,
  type RiskFinding,
  type ThreatRegister,
  type VerificationEvidenceInput,
  type AnalysisResult,
  type Severity,
  type HedgeConfig,
  type HedgeContext
} from "../domain/schemas.js";
import type { GraphDelta } from "../domain/schemas.js";
import { fileExists, readJsonFile, writeJsonFile } from "../utils/fs.js";
import { applyVerification } from "../verification/lifecycle.js";
import { stableHash } from "../utils/hash.js";
import { HEDGE_VERSION } from "../version.js";
import { isUnresolvedRisk } from "./status.js";

export async function loadThreatRegister(root: string): Promise<ThreatRegister> {
  const path = resolve(root, "threatmodel.json");
  if (!(await fileExists(path))) return emptyRegister();
  const raw = await readJsonFile<unknown>(path);
  const register = ThreatRegisterSchema.parse(raw);
  const warnings = validateThreatRegisterIntegrity(register, { raw });
  if (warnings.length) {
    throw new Error(`Hedge state integrity check failed: ${warnings.join(" ")}`);
  }
  return register;
}

export async function saveThreatRegister(root: string, register: ThreatRegister): Promise<void> {
  register.generatedAt = new Date().toISOString();
  if (register.graph) {
    register.stateIntegrity = {
      graphHash: stableHash(register.graph, 64),
      registerHash: undefined,
      algorithm: "sha256-stable-json-v2",
      configHash: register.stateIntegrity?.configHash,
      contextHash: register.stateIntegrity?.contextHash,
      sourceCommit: register.stateIntegrity?.sourceCommit ?? process.env.GITHUB_SHA,
      toolVersion: HEDGE_VERSION
    };
  } else {
    register.stateIntegrity = undefined;
  }
  if (register.stateIntegrity) {
    register.stateIntegrity.registerHash = threatRegisterStateHash(register);
  }
  await writeJsonFile(resolve(root, "threatmodel.json"), ThreatRegisterSchema.parse(register));
}

export function validateThreatRegisterIntegrity(
  register: ThreatRegister,
  options: { raw?: unknown } = {}
): string[] {
  if (!register.stateIntegrity || !register.graph) return [];
  const warnings: string[] = [];
  const actualGraph = stableHash(register.graph, 64);
  if (actualGraph !== register.stateIntegrity.graphHash) {
    warnings.push(
      `Stored graph digest ${register.stateIntegrity.graphHash} does not match computed digest ${actualGraph}.`
    );
  }
  if (register.stateIntegrity.registerHash) {
    if (register.stateIntegrity.algorithm === "sha256-stable-json-v2") {
      const actualRegister = threatRegisterStateHash(register);
      if (actualRegister !== register.stateIntegrity.registerHash) {
        const legacyV04Hash = isLegacyV04Register(options.raw, register)
          ? threatRegisterStateHashV04(register)
          : undefined;
        if (legacyV04Hash !== register.stateIntegrity.registerHash) {
          warnings.push(
            `Stored register digest ${register.stateIntegrity.registerHash} does not match computed digest ${actualRegister}.`
          );
        }
      }
    }
    // Registers written before v0.4 did not declare a durable register hashing
    // algorithm. Their graph digest is still verified, but the register-level
    // digest is upgraded on the next successful write rather than being
    // treated as authoritative under a different serializer.
  }
  return warnings;
}

export function validateThreatRegisterBindings(
  register: ThreatRegister,
  options: { config?: HedgeConfig; context?: HedgeContext; sourceCommit?: string }
): string[] {
  if (!register.stateIntegrity) return [];
  const warnings: string[] = [];
  if (options.config && register.stateIntegrity.configHash) {
    const actual = stableHash(options.config, 64);
    if (actual !== register.stateIntegrity.configHash) {
      warnings.push(
        `Stored policy digest ${register.stateIntegrity.configHash} does not match the current trusted policy digest ${actual}.`
      );
    }
  }
  if (options.context && register.stateIntegrity.contextHash) {
    const actual = stableHash(options.context, 64);
    if (actual !== register.stateIntegrity.contextHash) {
      warnings.push(
        `Stored context digest ${register.stateIntegrity.contextHash} does not match the current reviewed context digest ${actual}.`
      );
    }
  }
  if (
    options.sourceCommit &&
    register.stateIntegrity.sourceCommit &&
    options.sourceCommit !== register.stateIntegrity.sourceCommit
  ) {
    warnings.push(
      `The stored model was generated at ${register.stateIntegrity.sourceCommit}, not the current trusted revision ${options.sourceCommit}.`
    );
  }
  return warnings;
}

export function bindThreatRegisterState(
  register: ThreatRegister,
  metadata: { configHash?: string; contextHash?: string; sourceCommit?: string }
): void {
  register.stateIntegrity = register.graph
    ? {
        graphHash: stableHash(register.graph, 64),
        registerHash: undefined,
        algorithm: "sha256-stable-json-v2",
        configHash: metadata.configHash,
        contextHash: metadata.contextHash,
        sourceCommit: metadata.sourceCommit ?? process.env.GITHUB_SHA,
        toolVersion: HEDGE_VERSION
      }
    : undefined;
  if (register.stateIntegrity) {
    register.stateIntegrity.registerHash = threatRegisterStateHash(register);
  }
}

export function mergeFindings(
  register: ThreatRegister,
  proposals: RiskFinding[]
): { register: ThreatRegister; runFindings: RiskFinding[] } {
  const byFingerprint = new Map(register.findings.map((finding) => [finding.fingerprint, finding]));
  const runFindings: RiskFinding[] = [];

  for (const proposal of proposals) {
    const existing = byFingerprint.get(proposal.fingerprint);
    if (existing) {
      existing.updatedAt = new Date().toISOString();
      existing.title = proposal.title;
      existing.severity = proposal.severity;
      existing.origin = proposal.origin;
      existing.evidence = proposal.evidence;
      existing.existingControls = proposal.existingControls;
      existing.missingControls = proposal.missingControls;
      existing.confidence = proposal.confidence;
      existing.suggestedTest = proposal.suggestedTest;
      existing.remediationPrompt = proposal.remediationPrompt;
      // Accepted risks retain their recorded decision. A previously verified or closed
      // risk must reopen when the same active fingerprint returns.
      if (existing.status !== "accepted") existing.status = "open";
      runFindings.push(existing);
      continue;
    }

    const id = `HEDGE-${String(register.nextRiskNumber).padStart(3, "0")}`;
    register.nextRiskNumber += 1;
    const created = { ...proposal, id };
    register.findings.push(created);
    byFingerprint.set(created.fingerprint, created);
    runFindings.push(created);
  }

  return { register, runFindings };
}

export function markMissingFindingsAsMitigated(
  register: ThreatRegister,
  activeFindings: RiskFinding[],
  delta: GraphDelta,
  options: { modelAnalysisCompleted?: boolean; analysisComplete?: boolean } = {}
): RiskFinding[] {
  // Missing evidence is not evidence of mitigation when collection, parsing, or
  // framework coverage was incomplete. Leave lifecycle state untouched.
  if (options.analysisComplete === false) return [];
  const active = new Set(activeFindings.map((finding) => finding.fingerprint));
  const touchedFiles = deltaTouchedFiles(delta);
  const transitions: RiskFinding[] = [];

  for (const finding of register.findings) {
    if (active.has(finding.fingerprint)) continue;
    if (!["open", "verification-available"].includes(finding.status)) continue;
    if (finding.origin === "model" && !options.modelAnalysisCompleted) continue;
    if (finding.origin === "unknown" && !options.modelAnalysisCompleted) continue;
    if (!finding.evidence.some((evidence) => touchedFiles.has(evidence.file))) continue;
    finding.status = "mitigation-detected";
    finding.updatedAt = new Date().toISOString();
    transitions.push(finding);
  }

  return transitions;
}

export function acceptRisk(
  register: ThreatRegister,
  riskId: string,
  reason: string,
  acceptedBy: string
): RiskFinding {
  const finding = requireFinding(register, riskId);
  const normalizedReason = reason
    .replace(/[\r\n\t]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!normalizedReason) throw new Error("Risk acceptance requires a non-empty reason.");
  if (normalizedReason.length > 1000) {
    throw new Error("Risk acceptance reasons are limited to 1000 characters.");
  }
  const acceptedAt = new Date().toISOString();
  finding.status = "accepted";
  finding.updatedAt = acceptedAt;
  register.acceptedRisks = register.acceptedRisks.filter((item) => item.riskId !== finding.id);
  register.acceptedRisks.push({
    riskId: finding.id,
    reason: normalizedReason,
    acceptedBy,
    acceptedAt
  });
  return finding;
}

export function recordVerification(
  register: ThreatRegister,
  riskId: string,
  input: VerificationEvidenceInput
): RiskFinding {
  const finding = requireFinding(register, riskId);
  const evidence = VerificationEvidenceSchema.parse(input);
  const updated = applyVerification(finding, evidence);
  const index = register.findings.findIndex((candidate) => candidate.id === finding.id);
  register.findings[index] = updated;
  return updated;
}

export function requireFinding(register: ThreatRegister, riskId: string): RiskFinding {
  const normalized = riskId.toUpperCase();
  const finding = register.findings.find((item) => item.id === normalized);
  if (!finding) throw new Error(`Risk ${normalized} was not found.`);
  return finding;
}

export function emptyRegister(): ThreatRegister {
  return {
    schemaVersion: "0.1",
    generatedAt: new Date().toISOString(),
    stateIntegrity: undefined,
    nextRiskNumber: 1,
    graph: undefined,
    findings: [],
    invariantEvaluations: [],
    runs: [],
    acceptedRisks: []
  };
}

function deltaTouchedFiles(delta: GraphDelta): Set<string> {
  const evidence = [
    ...delta.addedNodes.flatMap((node) => node.evidence),
    ...delta.removedNodes.flatMap((node) => node.evidence),
    ...delta.changedNodes.flatMap((pair) => [...pair.before.evidence, ...pair.after.evidence]),
    ...delta.addedEdges.flatMap((edge) => edge.evidence),
    ...delta.removedEdges.flatMap((edge) => edge.evidence),
    ...delta.changedEdges.flatMap((pair) => [...pair.before.evidence, ...pair.after.evidence])
  ];
  return new Set(evidence.map((item) => item.file));
}

export function recordRun(
  register: ThreatRegister,
  options: {
    architectureChanged: boolean;
    analysis?: AnalysisResult;
    sourceCommit?: string;
  }
): void {
  if (!register.graph) return;
  const openFindings = register.findings.filter(isUnresolvedRisk);
  const graphHash = stableHash(register.graph, 64);
  const recordedAt = new Date().toISOString();
  const sourceCommit = options.sourceCommit ?? process.env.GITHUB_SHA;
  const id = stableHash(
    {
      graphHash,
      sourceCommit,
      architectureChanged: options.architectureChanged,
      findings: openFindings.map((finding) => [finding.id, finding.fingerprint, finding.severity]),
      model: options.analysis?.model
    },
    24
  );
  const existing = register.runs.findIndex((run) => run.id === id);
  const run = {
    id,
    recordedAt,
    sourceCommit,
    graphHash,
    nodeCount: register.graph.nodes.length,
    edgeCount: register.graph.edges.length,
    openRiskCount: openFindings.length,
    highestSeverity: highestSeverity(openFindings.map((finding) => finding.severity)),
    architectureChanged: options.architectureChanged,
    model: options.analysis?.model,
    modelRoute: options.analysis?.modelRoute,
    inputTokens: options.analysis?.usage?.inputTokens,
    outputTokens: options.analysis?.usage?.outputTokens,
    totalTokens: options.analysis?.usage?.totalTokens,
    cachedInputTokens: options.analysis?.usage?.cachedInputTokens,
    reasoningTokens: options.analysis?.usage?.reasoningTokens,
    modelCalls: options.analysis?.usage?.modelCalls
  };
  if (existing >= 0) register.runs[existing] = run;
  else register.runs.push(run);
  register.runs = register.runs.slice(-100);
}

export function threatRegisterStateHash(register: ThreatRegister): string {
  // Hash the schema-normalized state. Zod defaults (for example origin,
  // verification history, and tool version) must be applied before computing
  // the digest or a freshly written register would fail integrity validation
  // immediately after it is parsed back from disk.
  const canonical = ThreatRegisterSchema.parse(register);
  return stableHash(
    {
      schemaVersion: canonical.schemaVersion,
      nextRiskNumber: canonical.nextRiskNumber,
      graph: canonical.graph,
      findings: canonical.findings,
      invariantEvaluations: canonical.invariantEvaluations ?? [],
      runs: canonical.runs,
      acceptedRisks: canonical.acceptedRisks
    },
    64
  );
}

function isLegacyV04Register(raw: unknown, register: ThreatRegister): boolean {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
  const record = raw as Record<string, unknown>;
  if (Object.prototype.hasOwnProperty.call(record, "invariantEvaluations")) return false;
  return register.stateIntegrity?.toolVersion?.startsWith("0.4.") === true;
}

function threatRegisterStateHashV04(register: ThreatRegister): string {
  const canonical = ThreatRegisterSchema.parse(register);
  return stableHash(
    {
      schemaVersion: canonical.schemaVersion,
      nextRiskNumber: canonical.nextRiskNumber,
      graph: canonical.graph,
      findings: canonical.findings,
      runs: canonical.runs,
      acceptedRisks: canonical.acceptedRisks
    },
    64
  );
}

function highestSeverity(values: Severity[]): Severity {
  const order: Severity[] = ["info", "low", "medium", "high", "critical"];
  return values.reduce(
    (highest, value) => (order.indexOf(value) > order.indexOf(highest) ? value : highest),
    "info"
  );
}
