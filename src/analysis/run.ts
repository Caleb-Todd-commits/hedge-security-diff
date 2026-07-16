import type {
  AnalysisResult,
  AttackSurfaceGraph,
  GraphDelta,
  HedgeConfig,
  RiskFinding
} from "../domain/schemas.js";
import { analyzeWithHeuristics } from "./heuristics.js";
import {
  ModelRouter,
  type ModelRunResult,
  type ModelUsage,
  type TriageRunResult
} from "../model/client.js";
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
  const forcedDeepAnalysis = requiresDeepAnalysisDeterministically(
    options.delta,
    deterministicFindings
  );

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
        model: "deterministic-only",
        modelRoute: "deterministic"
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

  // The deterministic result already contains an evidence-linked recommendation.
  // Spending on model triage cannot change its trusted decision, so reserve model
  // calls for ambiguous or deterministically sensitive architecture changes.
  if (deterministicFindings.length > 0 && !forcedDeepAnalysis) {
    return finalizeAnalysis(
      {
        summary: `Hedge surfaced ${deterministicFindings.length} evidence-linked risk(s) using deterministic analysis; model reasoning was not needed.`,
        surfaceChanged: true,
        findings: deterministicFindings,
        integrity: {
          untrustedInstructionsObserved: instructionLike,
          analysisBoundaryHeld: true,
          notes: [
            "Model reasoning was skipped because deterministic evidence already supported the recommendation."
          ]
        },
        limitations: [],
        model: "deterministic-only",
        modelRoute: "deterministic"
      },
      options,
      invariantAnalysis.evaluations
    );
  }

  let triageRun: TriageRunResult | undefined;
  if (!forcedDeepAnalysis) {
    try {
      triageRun =
        options.recordedModel?.triage ??
        (router ? await router.triage(options.delta, options.patch) : undefined);
      if (!triageRun) throw new Error("No live or recorded triage result was available.");
    } catch (error) {
      return finalizeAnalysis(
        {
          ...deterministicFallback(
            deterministicFindings,
            instructionLike,
            `GPT-5.6 triage failed; deterministic findings were preserved: ${safeError(error)}`
          ),
          modelRoute: "fallback"
        },
        options,
        invariantAnalysis.evaluations
      );
    }
    if (!triageRun.result.deepAnalysisRequired) {
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
          modelRoute: "triage",
          usage: triageRun.usage
        },
        options,
        invariantAnalysis.evaluations
      );
    }
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
      `GPT-5.6 deep analysis failed${triageRun ? " after triage" : ""}; deterministic findings were preserved: ${safeError(error)}`
    );
    return finalizeAnalysis(
      {
        ...fallback,
        usage: triageRun?.usage,
        model: triageRun ? `${triageRun.model} → fallback` : "deterministic-fallback",
        modelRoute: "fallback"
      },
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
          ...(forcedDeepAnalysis
            ? [
                "Deep analysis was selected directly by deterministic graph-delta policy; the redundant triage call was skipped."
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
      modelRoute: triageRun ? "triage-analysis" : "analysis",
      usage: triageRun ? sumUsage(triageRun.usage, modelResult.usage) : modelResult.usage
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
  if (deterministicFindings.some((finding) => severityRank(finding.severity) >= 3)) return true;

  const sensitiveKinds = new Set(["auth-control", "authorization-control", "secret"]);
  const sensitiveNode = (node: GraphDelta["addedNodes"][number]): boolean =>
    sensitiveKinds.has(node.kind) ||
    node.trustZone === "privileged" ||
    (node.kind === "entrypoint" && node.trustZone === "public");
  if (delta.addedNodes.some(sensitiveNode)) return true;
  if (
    delta.removedNodes.some(
      (node) => sensitiveKinds.has(node.kind) || node.trustZone === "privileged"
    )
  )
    return true;
  if (
    delta.changedNodes.some(
      ({ before, after }) =>
        sensitiveNode(before) || sensitiveNode(after) || confirmedControlWasRemoved(before, after)
    )
  )
    return true;

  const sensitiveFlowKinds = new Set(["crosses-trust-boundary", "uses-secret"]);
  const sensitiveControlKinds = new Set([
    "authenticates",
    "authorizes",
    "crosses-trust-boundary",
    "uses-secret"
  ]);
  return (
    delta.addedEdges.some((edge) => sensitiveFlowKinds.has(edge.kind)) ||
    delta.removedEdges.some((edge) => sensitiveControlKinds.has(edge.kind)) ||
    delta.changedEdges.some(
      ({ before, after }) =>
        sensitiveControlKinds.has(before.kind) ||
        sensitiveControlKinds.has(after.kind) ||
        confirmedControlWasRemoved(before, after)
    )
  );
}

function confirmedControlWasRemoved(
  before: GraphDelta["addedNodes"][number] | GraphDelta["addedEdges"][number],
  after: GraphDelta["addedNodes"][number] | GraphDelta["addedEdges"][number]
): boolean {
  const trustedBefore = new Set(
    before.controls
      .filter((control) => control.assurance === "trusted" || control.assurance === "confirmed")
      .map((control) => control.type)
  );
  const trustedAfter = new Set(
    after.controls
      .filter((control) => control.assurance === "trusted" || control.assurance === "confirmed")
      .map((control) => control.type)
  );
  return [...trustedBefore].some((control) => !trustedAfter.has(control));
}

function severityRank(severity: RiskFinding["severity"]): number {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[severity];
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

function sumUsage(first?: ModelUsage, second?: ModelUsage): ModelUsage | undefined {
  if (!first && !second) return undefined;
  return {
    ...sumUsageMetric("inputTokens", first, second),
    ...sumUsageMetric("outputTokens", first, second),
    ...sumUsageMetric("totalTokens", first, second),
    ...sumUsageMetric("cachedInputTokens", first, second),
    ...sumUsageMetric("reasoningTokens", first, second),
    ...sumUsageMetric("modelCalls", first, second)
  };
}

function sumUsageMetric(
  key: keyof ModelUsage,
  first?: ModelUsage,
  second?: ModelUsage
): Partial<ModelUsage> {
  if (first?.[key] === undefined && second?.[key] === undefined) return {};
  return { [key]: (first?.[key] ?? 0) + (second?.[key] ?? 0) };
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
