import type {
  AnalysisResult,
  AttackSurfaceGraph,
  GraphDelta,
  HedgeConfig,
  RiskFinding
} from "../domain/schemas.js";
import { analyzeWithHeuristics } from "./heuristics.js";
import { ModelRouter, type ModelRunResult, type TriageRunResult } from "../model/client.js";
import { containsInstructionLikeContent } from "../security/untrusted.js";
import { analyzeWithCustomPolicies } from "./policies.js";
import { analyzeSecurityInvariants } from "./invariants.js";
import { buildInferences, buildObservations } from "./observations.js";
import { buildDecisions } from "./decisions.js";
import { deriveAnalysisHealth } from "./health.js";

type AnalysisCore = Omit<
  AnalysisResult,
  "observations" | "inferences" | "decisions" | "invariantEvaluations"
>;

export interface RunAnalysisOptions {
  graph: AttackSurfaceGraph;
  delta: GraphDelta;
  patch: string;
  config: HedgeConfig;
  apiKey?: string;
  recordedModel?: {
    triage?: TriageRunResult;
    analysis?: ModelRunResult;
  };
  coverage?: AnalysisResult["coverage"];
  healthReasons?: string[];
}

/** Recompute derived layers after lifecycle IDs/statuses are merged from trusted state. */
export function rebuildAnalysisLayers(
  analysis: AnalysisResult,
  findings: RiskFinding[],
  delta: GraphDelta,
  config: HedgeConfig
): AnalysisResult {
  const invariantEvaluations = analysis.invariantEvaluations ?? [];
  const observations = buildObservations(delta, invariantEvaluations);
  const inferences = buildInferences(findings, observations, analysis.model);
  const decisions = buildDecisions(
    findings,
    invariantEvaluations,
    observations,
    inferences,
    config.fail_on,
    analysis.analysisHealth
  );
  return { ...analysis, findings, observations, inferences, decisions };
}

export async function runAnalysis(options: RunAnalysisOptions): Promise<AnalysisResult> {
  const invariantAnalysis = analyzeSecurityInvariants(options.delta, options.config.invariants, {
    coverage: options.coverage ?? options.graph.coverage
  });
  const deterministicFindings = mergeByFingerprint(
    mergeByFingerprint(
      analyzeWithHeuristics(options.delta, options.graph),
      analyzeWithCustomPolicies(options.delta, options.config.policies)
    ),
    invariantAnalysis.findings
  );
  const instructionLike = containsInstructionLikeContent(options.patch);

  if (!options.apiKey && !options.recordedModel) {
    return finalizeAnalysis(
      {
        summary: deterministicFindings.length
          ? `Hedge surfaced ${deterministicFindings.length} evidence-linked risk(s) using deterministic analysis. Model reasoning was skipped because no API key was supplied.`
          : "A security architecture delta was detected, but deterministic rules did not surface a concrete risk.",
        surfaceChanged: true,
        findings: deterministicFindings,
        integrity: {
          untrustedInstructionsObserved: instructionLike,
          analysisBoundaryHeld: true,
          notes: [
            "Offline analysis mode: repository content was parsed as data and no model call was made."
          ]
        },
        limitations: ["GPT-5.6 architectural interpretation was not run."],
        model: "deterministic-only"
      },
      options,
      invariantAnalysis.evaluations
    );
  }

  const router = options.apiKey
    ? new ModelRouter({
        apiKey: options.apiKey,
        triageModel: options.config.models.triage,
        analysisModel: options.config.models.analysis
      })
    : undefined;

  let triageRun;
  try {
    triageRun =
      options.recordedModel?.triage ??
      (router ? await router.triage(options.delta, options.patch) : undefined);
    if (!triageRun) throw new Error("No live or recorded triage result was available.");
  } catch (error) {
    return finalizeAnalysis(
      deterministicFallback(
        deterministicFindings,
        instructionLike,
        `GPT-5.6 triage failed; deterministic findings were preserved: ${safeError(error)}`
      ),
      options,
      invariantAnalysis.evaluations
    );
  }
  const triage = triageRun.result;
  const forcedDeepAnalysis = requiresDeepAnalysisDeterministically(
    options.delta,
    deterministicFindings
  );
  if (!triage.deepAnalysisRequired && !forcedDeepAnalysis) {
    return finalizeAnalysis(
      {
        summary:
          "A security architecture delta was detected, but deterministic rules did not surface a concrete risk and deep model analysis was not required.",
        surfaceChanged: true,
        findings: deterministicFindings,
        integrity: {
          untrustedInstructionsObserved: instructionLike,
          analysisBoundaryHeld: true,
          notes: ["Luna triage did not request deep analysis."]
        },
        limitations: [],
        model: triageRun.model,
        usage: triageRun.usage
      },
      options,
      invariantAnalysis.evaluations
    );
  }

  let modelResult;
  try {
    modelResult =
      options.recordedModel?.analysis ??
      (router ? await router.analyze(options.graph, options.delta, options.patch) : undefined);
    if (!modelResult) throw new Error("No live or recorded deep-analysis result was available.");
  } catch (error) {
    const fallback = deterministicFallback(
      deterministicFindings,
      instructionLike,
      `GPT-5.6 deep analysis failed after triage; deterministic findings were preserved: ${safeError(error)}`
    );
    return finalizeAnalysis(
      { ...fallback, usage: triageRun.usage, model: `${triageRun.model} → fallback` },
      options,
      invariantAnalysis.evaluations
    );
  }
  const evidenceLinkedFindings = mergeByFingerprint(deterministicFindings, modelResult.findings);
  return finalizeAnalysis(
    {
      summary: evidenceLinkedFindings.length
        ? `Hedge surfaced ${evidenceLinkedFindings.length} evidence-linked risk(s) across deterministic analysis and validated model inference.`
        : "A security architecture delta was detected, but no evidence-linked design risk was surfaced.",
      surfaceChanged: true,
      findings: evidenceLinkedFindings,
      integrity: {
        untrustedInstructionsObserved: modelResult.integrity.untrustedInstructionsObserved,
        analysisBoundaryHeld: modelResult.integrity.analysisBoundaryHeld,
        notes: [
          "Model output passed schema, instruction-boundary, and exact evidence-reference validation; free-form model summary text was not published.",
          ...(forcedDeepAnalysis && !triage.deepAnalysisRequired
            ? [
                "Deep analysis was enforced by deterministic graph-delta policy despite the triage result."
              ]
            : [])
        ]
      },
      limitations:
        modelResult.rejectedProposalCount && modelResult.rejectedProposalCount > 0
          ? [
              `${modelResult.rejectedProposalCount} model proposal(s) were omitted because their scope or evidence did not resolve exactly.`
            ]
          : [],
      model: modelResult.model,
      usage: sumUsage(triageRun.usage, modelResult.usage)
    },
    options,
    invariantAnalysis.evaluations
  );
}

function finalizeAnalysis(
  result: AnalysisCore,
  options: RunAnalysisOptions,
  invariantEvaluations: ReturnType<typeof analyzeSecurityInvariants>["evaluations"]
): AnalysisResult {
  const coverage = options.coverage ?? options.graph.coverage;
  const analysisHealth = deriveAnalysisHealth(coverage, {
    modelDegraded: result.model?.includes("fallback") ?? false,
    modelReason: result.limitations.find((limitation) => /model|GPT/i.test(limitation)),
    reasons: options.healthReasons
  });
  const observations = buildObservations(options.delta, invariantEvaluations);
  const inferences = buildInferences(result.findings, observations, result.model);
  const decisions = buildDecisions(
    result.findings,
    invariantEvaluations,
    observations,
    inferences,
    options.config.fail_on,
    analysisHealth
  );
  return {
    ...result,
    confirmedNoDelta: false,
    coverage,
    analysisHealth,
    observations,
    inferences,
    decisions,
    invariantEvaluations
  };
}

export function requiresDeepAnalysisDeterministically(
  delta: GraphDelta,
  deterministicFindings: RiskFinding[] = []
): boolean {
  if (deterministicFindings.length > 0) return true;
  const importantKinds = new Set([
    "entrypoint",
    "auth-control",
    "authorization-control",
    "database",
    "data-model",
    "storage",
    "external-service",
    "secret",
    "component"
  ]);
  if (delta.addedNodes.some((node) => importantKinds.has(node.kind))) return true;
  if (delta.removedNodes.some((node) => importantKinds.has(node.kind))) return true;
  if (delta.changedNodes.some((pair) => importantKinds.has(pair.after.kind))) return true;
  const importantEdges = new Set([
    "calls",
    "reads",
    "writes",
    "authenticates",
    "authorizes",
    "crosses-trust-boundary",
    "uses-secret"
  ]);
  return (
    delta.addedEdges.some((edge) => importantEdges.has(edge.kind)) ||
    delta.removedEdges.some((edge) => importantEdges.has(edge.kind)) ||
    delta.changedEdges.some((pair) => importantEdges.has(pair.after.kind))
  );
}

function mergeByFingerprint(primary: RiskFinding[], secondary: RiskFinding[]): RiskFinding[] {
  const merged = new Map<string, RiskFinding>();
  for (const finding of [...primary, ...secondary]) {
    const existing = merged.get(finding.fingerprint);
    if (!existing || finding.confidence > existing.confidence)
      merged.set(finding.fingerprint, finding);
  }
  return [...merged.values()];
}

function sumUsage(
  first?: { inputTokens?: number; outputTokens?: number },
  second?: { inputTokens?: number; outputTokens?: number }
): { inputTokens?: number; outputTokens?: number } | undefined {
  if (!first && !second) return undefined;
  return {
    inputTokens: (first?.inputTokens ?? 0) + (second?.inputTokens ?? 0),
    outputTokens: (first?.outputTokens ?? 0) + (second?.outputTokens ?? 0)
  };
}

function deterministicFallback(
  findings: RiskFinding[],
  instructionLike: boolean,
  limitation: string
): AnalysisCore {
  return {
    summary: findings.length
      ? `Hedge preserved ${findings.length} deterministic evidence-linked risk(s) while model analysis was unavailable.`
      : "A security architecture delta was detected, but model analysis was unavailable and deterministic rules did not surface a concrete risk.",
    surfaceChanged: true,
    findings,
    integrity: {
      untrustedInstructionsObserved: instructionLike,
      analysisBoundaryHeld: true,
      notes: ["Model failure did not bypass deterministic analysis or evidence validation."]
    },
    limitations: [limitation],
    model: "deterministic-fallback"
  };
}

function safeError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message
    .replace(/(?:sk-[A-Za-z0-9_-]{8,}|Bearer\s+[A-Za-z0-9._-]+)/gi, "[redacted]")
    .slice(0, 300);
}
