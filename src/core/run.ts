import { resolve } from "node:path";
import type {
  AnalysisResult,
  AttackSurfaceGraph,
  GraphDelta,
  HedgeConfig,
  RiskFinding,
  ThreatRegister,
  HedgeContext
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
import { runAnalysis } from "../analysis/run.js";
import type { ModelRunResult, TriageRunResult } from "../model/client.js";
import { analyzeWithHeuristics } from "../analysis/heuristics.js";
import { analyzeWithCustomPolicies } from "../analysis/policies.js";
import { analyzeSecurityInvariants } from "../analysis/invariants.js";
import { stableHash } from "../utils/hash.js";
import { loadHedgeContext } from "../config/context.js";

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
  recordedModel?: {
    triage?: TriageRunResult;
    analysis?: ModelRunResult;
  };
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
    const invariantAnalysis = analyzeSecurityInvariants(initialDelta, config.invariants);
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
  const register = options.baselineRegister
    ? structuredClone(options.baselineRegister)
    : await loadThreatRegister(options.root);
  const graph = await buildAttackSurfaceGraph({
    root: options.root,
    config: options.config,
    repository: options.repository ?? "local",
    context: options.context
  });
  const baseline = register.graph ?? emptyGraph(graph.framework, graph.repository);
  const delta = diffGraphs(baseline, graph);
  const surfaceChanged = hasSecurityArchitectureDelta(delta);
  const reportPath = resolve(options.root, ".hedge", "report.md");
  const htmlReportPath = resolve(options.root, ".hedge", "report.html");
  const sarifPath = resolve(options.root, ".hedge", "results.sarif");
  const deltaPath = resolve(options.root, ".hedge", "delta.json");
  const analysisPath = resolve(options.root, ".hedge", "analysis.json");

  if (!surfaceChanged) {
    const analysis: AnalysisResult = {
      summary: "No evidence-linked security architecture delta was detected.",
      surfaceChanged: false,
      findings: [],
      integrity: {
        untrustedInstructionsObserved: false,
        analysisBoundaryHeld: true,
        notes: ["No model call was made."]
      },
      limitations: [],
      model: "none"
    };
    const report =
      "<!-- hedge-security-diff -->\nNo evidence-linked security architecture delta was detected.\n";
    await writeTextFile(reportPath, report);
    await writeTextFile(
      htmlReportPath,
      renderHtmlReport(baseline, graph, delta, analysis, [], { repository: graph.repository })
    );
    await writeJsonFile(sarifPath, renderSarif([], analysis));
    await writeJsonFile(deltaPath, delta);
    await writeJsonFile(analysisPath, analysis);
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
      lifecycleUpdates: []
    };
  }

  const analysis = await runAnalysis({
    graph,
    delta,
    patch: options.patch ?? "",
    config: options.config,
    apiKey: options.apiKey,
    recordedModel: options.recordedModel
  });
  const merged = mergeFindings(register, analysis.findings);
  const findings = merged.runFindings;
  const lifecycleUpdates = markMissingFindingsAsMitigated(merged.register, findings, delta, {
    modelAnalysisCompleted: analysis.model === options.config.models.analysis
  });
  const report = renderPullRequestReport(graph, delta, analysis, findings, lifecycleUpdates, {
    sourceCommit: options.sourceCommit
  });
  await writeTextFile(reportPath, report);
  await writeTextFile(
    htmlReportPath,
    renderHtmlReport(baseline, graph, delta, analysis, findings, { repository: graph.repository })
  );
  await writeJsonFile(sarifPath, renderSarif(findings, analysis));
  await writeJsonFile(deltaPath, delta);
  await writeJsonFile(analysisPath, { ...analysis, findings });

  if (options.persist) {
    merged.register.graph = graph;
    merged.register.invariantEvaluations = analysis.invariantEvaluations ?? [];
    recordRun(merged.register, {
      architectureChanged: surfaceChanged,
      analysis,
      sourceCommit: process.env.GITHUB_SHA
    });
    bindThreatRegisterState(merged.register, {
      configHash: stableHash(options.config, 64),
      contextHash: stableHash(options.context ?? (await loadHedgeContext(options.root)), 64),
      sourceCommit: process.env.GITHUB_SHA
    });
    await saveThreatRegister(options.root, merged.register);
    await writeTextFile(
      resolve(options.root, "THREATMODEL.md"),
      renderThreatModelDocument(graph, merged.register)
    );
  }

  return {
    graph,
    baseline,
    delta,
    analysis: { ...analysis, findings },
    findings,
    report,
    reportPath,
    htmlReportPath,
    sarifPath,
    deltaPath,
    analysisPath,
    surfaceChanged,
    register: merged.register,
    lifecycleUpdates
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
