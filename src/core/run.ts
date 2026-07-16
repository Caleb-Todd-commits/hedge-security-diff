import { resolve } from "node:path";
import type {
  AnalysisResult,
  AttackSurfaceGraph,
  GraphDelta,
  HedgeConfig,
  RiskFinding,
  ThreatRegister,
  HedgeContext,
  Coverage
} from "../domain/schemas.js";
import { buildAttackSurfaceGraph } from "../analyzers/build-graph.js";
import { diffGraphs, hasSecurityArchitectureDelta } from "../graph/diff.js";
import {
  bindThreatRegisterState,
  loadThreatRegister,
  markMissingFindingsAsMitigated,
  mergeFindings,
  recordRun,
  saveThreatRegister
} from "../register/store.js";
import { renderThreatModelDocument } from "../report/threatmodel.js";
import { renderPullRequestReport } from "../report/comment.js";
import { renderHtmlReport } from "../report/html.js";
import { renderSarif } from "../report/sarif.js";
import { writeJsonFile, writeTextFile } from "../utils/fs.js";
import { rebuildAnalysisLayers, runAnalysis } from "../analysis/run.js";
import type { ModelRunResult, TriageRunResult } from "../model/client.js";
import { analyzeWithHeuristics } from "../analysis/heuristics.js";
import { analyzeWithCustomPolicies } from "../analysis/policies.js";
import { analyzeSecurityInvariants } from "../analysis/invariants.js";
import { stableHash } from "../utils/hash.js";
import { loadHedgeContext } from "../config/context.js";
import { buildAttackSurfaceGraphAtCommit } from "../git/graph.js";
import { comparisonCoverage } from "../analysis/coverage.js";
import { deriveAnalysisHealth } from "../analysis/health.js";
import { buildDecisions } from "../analysis/decisions.js";
import { renderNoDeltaReport } from "../report/no-delta.js";

export interface InitResult {
  graph: AttackSurfaceGraph;
  register: ThreatRegister;
  threatModelPath: string;
  statePath: string;
}

export interface CheckOptions {
  root: string;
  config: HedgeConfig;
  patch?: string;
  apiKey?: string;
  repository?: string;
  persist?: boolean;
  baselineRegister?: ThreatRegister;
  context?: HedgeContext;
  sourceCommit?: string;
  baseRevision?: string;
  headRevision?: string;
  baselineGraph?: AttackSurfaceGraph;
  headGraph?: AttackSurfaceGraph;
  exactRevisions?: boolean;
  coverageDiagnostics?: Coverage["diagnostics"];
  recordedModel?: {
    triage?: TriageRunResult;
    analysis?: ModelRunResult;
  };
  /** Collection jobs analyze exact object bytes without writing into the target checkout. */
  writeArtifacts?: boolean;
}

export interface CheckResult {
  graph: AttackSurfaceGraph;
  delta: GraphDelta;
  analysis: AnalysisResult;
  findings: RiskFinding[];
  report: string;
  reportPath: string;
  htmlReportPath: string;
  sarifPath: string;
  deltaPath: string;
  analysisPath: string;
  baseline: AttackSurfaceGraph;
  surfaceChanged: boolean;
  register: ThreatRegister;
  lifecycleUpdates: RiskFinding[];
  exactRevisions: boolean;
  baseCommit?: string;
  headCommit?: string;
}

export async function initializeHedge(
  root: string,
  config: HedgeConfig,
  repository = "local"
): Promise<InitResult> {
  const graph = await buildAttackSurfaceGraph({ root, config, repository });
  const register = await loadThreatRegister(root);
  const baseline = register.graph ?? emptyGraph(graph.framework, graph.repository);
  const initialDelta = diffGraphs(baseline, graph);
  if (hasSecurityArchitectureDelta(initialDelta)) {
    const invariantAnalysis = analyzeSecurityInvariants(initialDelta, config.invariants, {
      coverage: graph.coverage
    });
    mergeFindings(register, [
      ...analyzeWithHeuristics(initialDelta, graph),
      ...analyzeWithCustomPolicies(initialDelta, config.policies),
      ...invariantAnalysis.findings
    ]);
    register.invariantEvaluations = invariantAnalysis.evaluations;
  }
  register.graph = graph;
  const context = await loadHedgeContext(root);
  recordRun(register, { architectureChanged: hasSecurityArchitectureDelta(initialDelta) });
  bindThreatRegisterState(register, {
    configHash: stableHash(config, 64),
    contextHash: stableHash(context, 64),
    sourceCommit: process.env.GITHUB_SHA
  });
  await saveThreatRegister(root, register);
  const threatModelPath = resolve(root, "THREATMODEL.md");
  await writeTextFile(threatModelPath, renderThreatModelDocument(graph, register));
  const graphPath = resolve(root, ".hedge", "graph.json");
  await writeJsonFile(graphPath, graph);
  return { graph, register, threatModelPath, statePath: resolve(root, "threatmodel.json") };
}

export async function checkHedge(options: CheckOptions): Promise<CheckResult> {
  if (options.writeArtifacts === false && options.persist) {
    throw new Error("A no-write collection cannot persist reports or register state.");
  }
  const register = options.baselineRegister
    ? structuredClone(options.baselineRegister)
    : await loadThreatRegister(options.root);
  let graph: AttackSurfaceGraph;
  let baseline: AttackSurfaceGraph;
  let baseCommit: string | undefined;
  let headCommit: string | undefined;
  let exactRevisions = options.exactRevisions ?? false;

  if (options.baseRevision && options.headRevision) {
    const [baseResult, headResult] = await Promise.all([
      buildAttackSurfaceGraphAtCommit({
        root: options.root,
        revision: options.baseRevision,
        config: options.config,
        repository: options.repository ?? "local",
        context: options.context,
        snapshot: "base"
      }),
      buildAttackSurfaceGraphAtCommit({
        root: options.root,
        revision: options.headRevision,
        config: options.config,
        repository: options.repository ?? "local",
        context: options.context,
        snapshot: "head"
      })
    ]);
    baseline = baseResult.graph;
    graph = headResult.graph;
    baseCommit = baseResult.commit;
    headCommit = headResult.commit;
    exactRevisions = true;
  } else {
    graph =
      options.headGraph ??
      (await buildAttackSurfaceGraph({
        root: options.root,
        config: options.config,
        repository: options.repository ?? "local",
        context: options.context,
        sourceCommit: options.sourceCommit,
        snapshot: "head"
      }));
    baseline = options.baselineGraph ?? register.graph ?? unavailableBaseline(graph);
    baseCommit = baseline.sourceCommit;
    headCommit = options.sourceCommit;
  }
  const coverage = comparisonCoverage(baseline, graph, options.coverageDiagnostics ?? []);
  const delta = diffGraphs(baseline, graph);
  const surfaceChanged = hasSecurityArchitectureDelta(delta);
  const reportPath = resolve(options.root, ".hedge", "report.md");
  const htmlReportPath = resolve(options.root, ".hedge", "report.html");
  const sarifPath = resolve(options.root, ".hedge", "results.sarif");
  const deltaPath = resolve(options.root, ".hedge", "delta.json");
  const analysisPath = resolve(options.root, ".hedge", "analysis.json");

  if (!surfaceChanged) {
    const analysisHealth = deriveAnalysisHealth(coverage, {
      reasons: exactRevisions
        ? []
        : ["Exact base and head revisions were not both available for this comparison."]
    });
    const confirmedNoDelta = exactRevisions && analysisHealth.status === "complete";
    const analysis: AnalysisResult = {
      summary: confirmedNoDelta
        ? "No evidence-linked security architecture delta was detected across the exact base and head revisions with complete supported coverage."
        : "No graph delta was observed, but incomplete coverage or revision provenance prevents a confirmed no-delta result.",
      surfaceChanged: false,
      confirmedNoDelta,
      coverage,
      analysisHealth,
      observations: [],
      inferences: [],
      decisions: buildDecisions([], [], [], [], options.config.fail_on, analysisHealth),
      invariantEvaluations: [],
      findings: [],
      integrity: {
        untrustedInstructionsObserved: false,
        analysisBoundaryHeld: true,
        notes: ["No model call was made."]
      },
      limitations: [],
      model: "none",
      modelRoute: "none"
    };
    const report = renderNoDeltaReport(analysis);
    if (options.writeArtifacts !== false) {
      await writeTextFile(reportPath, report);
      await writeTextFile(
        htmlReportPath,
        renderHtmlReport(baseline, graph, delta, analysis, [], { repository: graph.repository })
      );
      await writeJsonFile(sarifPath, renderSarif([], analysis));
      await writeJsonFile(deltaPath, delta);
      await writeJsonFile(analysisPath, analysis);
    }
    return {
      graph,
      baseline,
      delta,
      analysis,
      findings: [],
      report,
      reportPath,
      htmlReportPath,
      sarifPath,
      deltaPath,
      analysisPath,
      surfaceChanged,
      register,
      lifecycleUpdates: [],
      exactRevisions,
      baseCommit,
      headCommit
    };
  }

  const analysis = await runAnalysis({
    graph,
    delta,
    patch: options.patch ?? "",
    config: options.config,
    apiKey: options.apiKey,
    recordedModel: options.recordedModel,
    coverage,
    healthReasons: exactRevisions
      ? []
      : ["Exact base and head revisions were not both available for this comparison."]
  });
  const merged = mergeFindings(register, analysis.findings);
  const findings = merged.runFindings;
  const boundAnalysis = rebuildAnalysisLayers(analysis, findings, delta, options.config);
  const lifecycleUpdates = markMissingFindingsAsMitigated(merged.register, findings, delta, {
    modelAnalysisCompleted: boundAnalysis.model === options.config.models.analysis,
    analysisComplete: boundAnalysis.analysisHealth?.status === "complete"
  });
  const report = renderPullRequestReport(graph, delta, boundAnalysis, findings, lifecycleUpdates, {
    sourceCommit: headCommit ?? options.sourceCommit,
    repository: options.repository,
    baseCommit,
    headCommit
  });
  if (options.writeArtifacts !== false) {
    await writeTextFile(reportPath, report);
    await writeTextFile(
      htmlReportPath,
      renderHtmlReport(baseline, graph, delta, boundAnalysis, findings, {
        repository: graph.repository
      })
    );
    await writeJsonFile(sarifPath, renderSarif(findings, boundAnalysis));
    await writeJsonFile(deltaPath, delta);
    await writeJsonFile(analysisPath, boundAnalysis);
  }

  if (options.persist) {
    const persistedSourceCommit = headCommit ?? options.sourceCommit ?? process.env.GITHUB_SHA;
    merged.register.graph = graph;
    merged.register.invariantEvaluations = analysis.invariantEvaluations ?? [];
    recordRun(merged.register, {
      architectureChanged: surfaceChanged,
      analysis: boundAnalysis,
      sourceCommit: persistedSourceCommit
    });
    bindThreatRegisterState(merged.register, {
      configHash: stableHash(options.config, 64),
      contextHash: stableHash(options.context ?? (await loadHedgeContext(options.root)), 64),
      sourceCommit: persistedSourceCommit
    });
    await saveThreatRegister(options.root, merged.register);
    await writeJsonFile(resolve(options.root, ".hedge", "graph.json"), graph);
    await writeTextFile(
      resolve(options.root, "THREATMODEL.md"),
      renderThreatModelDocument(graph, merged.register)
    );
  }

  return {
    graph,
    baseline,
    delta,
    analysis: boundAnalysis,
    findings,
    report,
    reportPath,
    htmlReportPath,
    sarifPath,
    deltaPath,
    analysisPath,
    surfaceChanged,
    register: merged.register,
    lifecycleUpdates,
    exactRevisions,
    baseCommit,
    headCommit
  };
}

function emptyGraph(framework: string, repository: string): AttackSurfaceGraph {
  return {
    schemaVersion: "0.1",
    generatedAt: new Date(0).toISOString(),
    repository,
    framework,
    nodes: [],
    edges: [],
    assumptions: [],
    unknowns: [
      "No stored Hedge baseline was found; this run is treated as an initial surface inventory."
    ]
  };
}

function unavailableBaseline(head: AttackSurfaceGraph): AttackSurfaceGraph {
  return {
    ...structuredClone(head),
    generatedAt: new Date(0).toISOString(),
    sourceCommit: undefined,
    coverage: {
      status: "partial",
      discoveredFiles: 0,
      includedFiles: 0,
      includedBytes: 0,
      omitted: { fileLimit: 0, byteLimit: 0, unsafeOrUnreadable: 0, binary: 0 },
      diagnostics: [
        {
          code: "baseline-unavailable",
          phase: "analysis",
          snapshot: "base",
          message:
            "No exact or integrity-bound baseline graph was available; an empty comparison was not performed."
        }
      ]
    },
    assumptions: [...head.assumptions],
    unknowns: [
      ...head.unknowns,
      "No exact or integrity-bound baseline graph was available; this run cannot confirm change or no-change."
    ]
  };
}
