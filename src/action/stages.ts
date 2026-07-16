import * as github from "@actions/github";
import { lstat, mkdir, open, readFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import type {
  AnalysisResult,
  CollectionBundle,
  HedgeConfig,
  HedgeContext,
  ReasonBundle,
  RiskFinding,
  ThreatRegister
} from "../domain/schemas.js";
import { renderHtmlReport } from "../report/html.js";
import { renderPullRequestReport } from "../report/comment.js";
import { renderSarif } from "../report/sarif.js";
import { removePullRequestComments, upsertPullRequestComment } from "../github/comment.js";
import {
  createRunManifest,
  serializeRunManifest,
  verifyRunBundle
} from "../github/run-manifest.js";
import {
  createCollectionBundle,
  createReasonBundle,
  parseCollectionBundle,
  parseReasonBundle,
  serializePipelineBundle,
  verifyReasonAgainstCollection,
  type PipelineBindings
} from "../pipeline/bundles.js";
import {
  currentActionVersion,
  currentWorkflowRef,
  EXTRACTOR_VERSION,
  PIPELINE_SCHEMA_VERSION,
  PROMPT_VERSION,
  pipelineDigests
} from "../pipeline/metadata.js";
import type { CheckResult } from "../core/run.js";
import { rebuildAnalysisLayers, runAnalysis } from "../analysis/run.js";
import { emptyRegister, markMissingFindingsAsMitigated, mergeFindings } from "../register/store.js";
import { writeJsonFile, writeTextFile, fileExists } from "../utils/fs.js";
import { stableHash } from "../utils/hash.js";
import { renderNoDeltaReport } from "../report/no-delta.js";

export const COLLECTION_ARTIFACT = "collection.json";
export const COLLECTION_MANIFEST_ARTIFACT = "collection-manifest.json";
export const REASON_ARTIFACT = "reason.json";

export interface StagePaths {
  collectionPath: string;
  collectionManifestPath: string;
  reasonPath: string;
  manifestPath: string;
}

export function resolveStagePaths(root: string, inputs: Partial<StagePaths> = {}): StagePaths {
  return {
    collectionPath: resolve(root, inputs.collectionPath ?? ".hedge/pipeline/collection.json"),
    collectionManifestPath: resolve(
      root,
      inputs.collectionManifestPath ?? ".hedge/pipeline/collection-manifest.json"
    ),
    reasonPath: resolve(root, inputs.reasonPath ?? ".hedge/pipeline/reason.json"),
    manifestPath: resolve(root, inputs.manifestPath ?? ".hedge/pipeline/run-manifest.json")
  };
}

export function assertTrustedStagePaths(
  paths: StagePaths,
  command: "collect" | "reason" | "publish"
): void {
  if (process.env.GITHUB_ACTIONS !== "true") return;
  const runnerTemp = process.env.RUNNER_TEMP?.trim();
  if (!runnerTemp) throw new Error(`${command} requires the trusted runner temporary directory.`);
  const required =
    command === "collect"
      ? [paths.collectionPath, paths.collectionManifestPath]
      : command === "reason"
        ? [paths.collectionPath, paths.collectionManifestPath, paths.reasonPath, paths.manifestPath]
        : Object.values(paths);
  for (const path of required) {
    const rel = relative(resolve(runnerTemp), resolve(path));
    if (!rel || rel === ".." || rel.startsWith("../") || rel.startsWith("..\\")) {
      throw new Error(`${command} stage artifacts must use distinct files below runner.temp.`);
    }
  }
  if (new Set(required.map((path) => resolve(path))).size !== required.length) {
    throw new Error(`${command} stage artifact paths must be distinct.`);
  }
}

export async function writeCollectionStage(options: {
  paths: StagePaths;
  result: CheckResult;
  config: HedgeConfig;
  context: HedgeContext;
  register?: ThreatRegister;
  patch: string;
  repository: string;
  pullRequest: number;
  baseSha: string;
  headSha: string;
  workflowRef?: string;
  actionVersion?: string;
}): Promise<{ bundle: CollectionBundle; manifestPath: string }> {
  if (!options.result.exactRevisions || !options.result.baseCommit || !options.result.headCommit) {
    throw new Error("Collection requires an authoritative exact base/head comparison.");
  }
  if (
    options.result.baseCommit !== options.baseSha ||
    options.result.headCommit !== options.headSha
  ) {
    throw new Error("Collected graph revisions do not match the authorized pull request.");
  }
  const coverage = requireCoverage(options.result.analysis);
  const analysisHealth = requireHealth(options.result.analysis);
  const actionVersion = options.actionVersion ?? currentActionVersion();
  const workflowRef = options.workflowRef ?? currentWorkflowRef();
  const bundle = createCollectionBundle({
    schemaVersion: "0.1",
    repository: options.repository,
    pullRequest: options.pullRequest,
    baseSha: options.baseSha,
    headSha: options.headSha,
    workflowRef,
    actionVersion,
    config: options.config,
    context: options.context,
    baseline: options.result.baseline,
    graph: options.result.graph,
    delta: options.result.delta,
    patch: options.patch,
    coverage,
    analysisHealth,
    exactRevisions: true,
    analysis: options.result.analysis,
    register: options.register
  });
  const collectionBytes = serializePipelineBundle(bundle);
  const digests = pipelineDigests(options.config, options.context);
  const manifest = createRunManifest({
    repository: options.repository,
    pullRequest: options.pullRequest,
    baseSha: options.baseSha,
    headSha: options.headSha,
    workflowRef,
    actionVersion,
    extractorVersion: EXTRACTOR_VERSION,
    artifactSchemaVersion: PIPELINE_SCHEMA_VERSION,
    configDigest: digests.configDigest,
    contextDigest: digests.contextDigest,
    extractorDigest: digests.extractorDigest,
    schemaDigest: digests.schemaDigest,
    model: options.result.analysis.model ?? "none",
    coverage,
    analysisHealth,
    artifacts: { [COLLECTION_ARTIFACT]: collectionBytes }
  });

  const manifestBytes = serializeRunManifest(manifest);
  await writeBoundedFile(options.paths.collectionPath, collectionBytes);
  await writeBoundedFile(options.paths.collectionManifestPath, manifestBytes);
  return { bundle, manifestPath: options.paths.collectionManifestPath };
}

export async function runReasonStage(options: {
  paths: StagePaths;
  expected: PipelineBindings;
  apiKey?: string;
}): Promise<{ bundle: ReasonBundle; manifestPath: string }> {
  const [manifestBytes, collectionBytes] = await Promise.all([
    readFile(options.paths.collectionManifestPath),
    readFile(options.paths.collectionPath)
  ]);
  const verified = verifyRunBundle({
    manifest: manifestBytes,
    artifacts: { [COLLECTION_ARTIFACT]: collectionBytes },
    expected: options.expected
  });
  const collection = parseCollectionBundle(collectionBytes, options.expected);
  assertManifestDigests(verified.manifest, collection.config, collection.context, false);
  assertManifestAnalysisBindings(verified.manifest, collection.analysis);
  if (!collection.analysis.surfaceChanged) {
    throw new Error("Reasoning must not run when collection recorded no graph delta.");
  }

  const analysis = await runAnalysis({
    graph: collection.graph,
    delta: collection.delta,
    patch: collection.patch,
    config: collection.config,
    apiKey: options.apiKey,
    coverage: collection.coverage
  });
  const register = structuredClone(collection.register ?? emptyRegister());
  const merged = mergeFindings(register, analysis.findings);
  const findings = merged.runFindings;
  const boundAnalysis = rebuildAnalysisLayers(
    analysis,
    findings,
    collection.delta,
    collection.config
  );
  const lifecycleUpdates = markMissingFindingsAsMitigated(
    merged.register,
    findings,
    collection.delta,
    {
      modelAnalysisCompleted: boundAnalysis.model === collection.config.models.analysis,
      analysisComplete: boundAnalysis.analysisHealth?.status === "complete"
    }
  );
  const bundle = createReasonBundle({
    schemaVersion: "0.1",
    repository: collection.repository,
    pullRequest: collection.pullRequest,
    baseSha: collection.baseSha,
    headSha: collection.headSha,
    workflowRef: collection.workflowRef,
    actionVersion: collection.actionVersion,
    collectionManifestDigest: verified.manifest.manifestDigest,
    analysis: boundAnalysis,
    lifecycleUpdates
  });
  const reasonBytes = serializePipelineBundle(bundle);
  const digests = pipelineDigests(collection.config, collection.context);
  const manifest = createRunManifest({
    repository: collection.repository,
    pullRequest: collection.pullRequest,
    baseSha: collection.baseSha,
    headSha: collection.headSha,
    workflowRef: collection.workflowRef,
    actionVersion: collection.actionVersion,
    extractorVersion: EXTRACTOR_VERSION,
    artifactSchemaVersion: PIPELINE_SCHEMA_VERSION,
    promptVersion: PROMPT_VERSION,
    configDigest: digests.configDigest,
    contextDigest: digests.contextDigest,
    extractorDigest: digests.extractorDigest,
    schemaDigest: digests.schemaDigest,
    promptDigest: digests.promptDigest,
    model: boundAnalysis.model,
    coverage: requireCoverage(boundAnalysis),
    analysisHealth: requireHealth(boundAnalysis),
    artifacts: {
      [COLLECTION_ARTIFACT]: collectionBytes,
      [COLLECTION_MANIFEST_ARTIFACT]: manifestBytes,
      [REASON_ARTIFACT]: reasonBytes
    }
  });
  await writeBoundedFile(options.paths.reasonPath, reasonBytes);
  await writeBoundedFile(options.paths.manifestPath, serializeRunManifest(manifest));
  return { bundle, manifestPath: options.paths.manifestPath };
}

export interface PublishStageResult {
  analysis: AnalysisResult;
  reportPath: string;
  htmlReportPath: string;
  sarifPath: string;
  deltaPath: string;
  analysisPath: string;
  manifestPath: string;
  decision: "allow" | "warn" | "block";
}

export async function runPublishStage(options: {
  root: string;
  paths: StagePaths;
  token: string;
  dryRun?: boolean;
  workflowRef?: string;
  actionVersion?: string;
}): Promise<PublishStageResult> {
  const pullRequest = github.context.payload.pull_request;
  if (!pullRequest) throw new Error("Publish requires a pull_request workflow event.");
  const octokit = github.getOctokit(options.token);
  const { owner, repo } = github.context.repo;
  const current = await octokit.rest.pulls.get({ owner, repo, pull_number: pullRequest.number });
  const expected: PipelineBindings = {
    repository: `${owner}/${repo}`,
    pullRequest: pullRequest.number,
    baseSha: current.data.base.sha.toLowerCase(),
    headSha: current.data.head.sha.toLowerCase(),
    workflowRef: options.workflowRef ?? currentWorkflowRef(),
    actionVersion: options.actionVersion ?? currentActionVersion()
  };
  const collectionManifestBytes = await readFile(options.paths.collectionManifestPath);
  const collectionBytes = await readFile(options.paths.collectionPath);
  const hasReason = await fileExists(options.paths.reasonPath);
  const reasonBytes = hasReason ? await readFile(options.paths.reasonPath) : undefined;
  const collectionVerification = verifyRunBundle({
    manifest: collectionManifestBytes,
    artifacts: { [COLLECTION_ARTIFACT]: collectionBytes },
    expected
  });
  let reasonVerification: ReturnType<typeof verifyRunBundle> | undefined;
  if (reasonBytes) {
    const reasonManifestBytes = await readFile(options.paths.manifestPath);
    reasonVerification = verifyRunBundle({
      manifest: reasonManifestBytes,
      artifacts: {
        [COLLECTION_ARTIFACT]: collectionBytes,
        [COLLECTION_MANIFEST_ARTIFACT]: collectionManifestBytes,
        [REASON_ARTIFACT]: reasonBytes
      },
      expected
    });
  }
  const collection = parseCollectionBundle(collectionBytes, expected);
  assertManifestDigests(
    collectionVerification.manifest,
    collection.config,
    collection.context,
    false
  );
  assertManifestAnalysisBindings(collectionVerification.manifest, collection.analysis);

  let analysis = collection.analysis;
  let lifecycleUpdates: RiskFinding[] = [];
  if (collection.analysis.surfaceChanged) {
    if (!reasonBytes) throw new Error("Changed architecture requires a validated reason bundle.");
    const reason = parseReasonBundle(reasonBytes, expected);
    verifyReasonAgainstCollection(
      reason,
      collection,
      collectionVerification.manifest.manifestDigest
    );
    if (!reasonVerification) throw new Error("Reason manifest verification was not recorded.");
    assertManifestDigests(reasonVerification.manifest, collection.config, collection.context, true);
    assertManifestAnalysisBindings(reasonVerification.manifest, reason.analysis);
    analysis = reason.analysis;
    lifecycleUpdates = reason.lifecycleUpdates;
  } else if (!collection.analysis.confirmedNoDelta) {
    // Silence by default remains intact, but an incomplete no-change observation
    // must never remove a previous complete report.
    lifecycleUpdates = [];
  }
  validatePublishedEvidence(collection, analysis);

  const reportPath = resolve(options.root, ".hedge/report.md");
  const htmlReportPath = resolve(options.root, ".hedge/report.html");
  const sarifPath = resolve(options.root, ".hedge/results.sarif");
  const deltaPath = resolve(options.root, ".hedge/delta.json");
  const analysisPath = resolve(options.root, ".hedge/analysis.json");
  const report = collection.analysis.surfaceChanged
    ? renderPullRequestReport(
        collection.graph,
        collection.delta,
        analysis,
        analysis.findings,
        lifecycleUpdates,
        {
          repository: collection.repository,
          baseCommit: collection.baseSha,
          headCommit: collection.headSha
        }
      )
    : renderNoDeltaReport(analysis);
  await writeTextFile(reportPath, report);
  await writeTextFile(
    htmlReportPath,
    renderHtmlReport(
      collection.baseline,
      collection.graph,
      collection.delta,
      analysis,
      analysis.findings,
      { repository: collection.repository }
    )
  );
  await writeJsonFile(sarifPath, renderSarif(analysis.findings, analysis));
  await writeJsonFile(deltaPath, collection.delta);
  await writeJsonFile(analysisPath, analysis);

  // Re-fetch immediately before mutating GitHub so an obsolete run cannot
  // overwrite the latest pull-request head.
  const fresh = await octokit.rest.pulls.get({ owner, repo, pull_number: pullRequest.number });
  if (
    fresh.data.head.sha.toLowerCase() !== collection.headSha ||
    fresh.data.base.sha.toLowerCase() !== collection.baseSha
  ) {
    throw new Error("Run became stale before publication; current pull-request revisions changed.");
  }
  if (!options.dryRun) {
    if (collection.analysis.surfaceChanged) await upsertPullRequestComment(options.token, report);
    else if (analysis.confirmedNoDelta) await removePullRequestComments(options.token);
  }

  return {
    analysis,
    reportPath,
    htmlReportPath,
    sarifPath,
    deltaPath,
    analysisPath,
    manifestPath: hasReason ? options.paths.manifestPath : options.paths.collectionManifestPath,
    decision: recordedDecision(analysis)
  };
}

function assertManifestAnalysisBindings(
  manifest: ReturnType<typeof verifyRunBundle>["manifest"],
  analysis: AnalysisResult
): void {
  const coverage = requireCoverage(analysis);
  const health = requireHealth(analysis);
  if (stableHash(manifest.coverage, 64) !== stableHash(coverage, 64)) {
    throw new Error("Run manifest coverage does not match its analysis bundle.");
  }
  if (stableHash(manifest.analysisHealth, 64) !== stableHash(health, 64)) {
    throw new Error("Run manifest analysis health does not match its analysis bundle.");
  }
  if (manifest.model !== (analysis.model ?? "none")) {
    throw new Error("Run manifest model does not match its analysis bundle.");
  }
}

function validatePublishedEvidence(collection: CollectionBundle, analysis: AnalysisResult): void {
  const subjects = new Set<string>();
  for (const node of collection.delta.addedNodes) subjects.add(node.id);
  for (const node of collection.delta.removedNodes) subjects.add(node.id);
  for (const pair of collection.delta.changedNodes) {
    subjects.add(pair.before.id);
    subjects.add(pair.after.id);
  }
  for (const edge of collection.delta.addedEdges) {
    subjects.add(edge.id);
    subjects.add(edge.from);
    subjects.add(edge.to);
  }
  for (const edge of collection.delta.removedEdges) {
    subjects.add(edge.id);
    subjects.add(edge.from);
    subjects.add(edge.to);
  }
  for (const pair of collection.delta.changedEdges) {
    subjects.add(pair.before.id);
    subjects.add(pair.before.from);
    subjects.add(pair.before.to);
    subjects.add(pair.after.id);
    subjects.add(pair.after.from);
    subjects.add(pair.after.to);
  }

  for (const finding of analysis.findings) {
    if (!finding.evidence.length) {
      throw new Error(`Published finding ${finding.id} has no exact evidence.`);
    }
    for (const evidence of finding.evidence) {
      if (!evidence.snapshot) {
        throw new Error(`Published finding ${finding.id} contains evidence without a snapshot.`);
      }
      const expectedCommit = evidence.snapshot === "base" ? collection.baseSha : collection.headSha;
      if (
        evidence.commit !== expectedCommit ||
        !evidence.subjectId ||
        !subjects.has(evidence.subjectId)
      ) {
        throw new Error(`Published finding ${finding.id} contains unbound evidence.`);
      }
    }
  }
}

function assertManifestDigests(
  manifest: ReturnType<typeof verifyRunBundle>["manifest"],
  config: HedgeConfig,
  context: HedgeContext,
  requirePrompt: boolean
): void {
  if (manifest.extractorVersion !== EXTRACTOR_VERSION) {
    throw new Error("Run manifest extractor-version binding failed.");
  }
  if (manifest.artifactSchemaVersion !== PIPELINE_SCHEMA_VERSION) {
    throw new Error("Run manifest artifact-schema-version binding failed.");
  }
  if (requirePrompt && manifest.promptVersion !== PROMPT_VERSION) {
    throw new Error("Run manifest prompt-version binding failed.");
  }
  const expected = pipelineDigests(config, context);
  const pairs: Array<[string, string | undefined, string]> = [
    [expected.configDigest, manifest.configDigest, "configuration"],
    [expected.contextDigest, manifest.contextDigest, "context"],
    [expected.extractorDigest, manifest.extractorDigest, "extractor"],
    [expected.schemaDigest, manifest.schemaDigest, "schema"]
  ];
  if (requirePrompt) pairs.push([expected.promptDigest, manifest.promptDigest, "prompt"]);
  for (const [value, actual, label] of pairs) {
    if (value !== actual) throw new Error(`Run manifest ${label} digest binding failed.`);
  }
}

function requireCoverage(analysis: AnalysisResult): NonNullable<AnalysisResult["coverage"]> {
  if (!analysis.coverage) throw new Error("Analysis did not record coverage.");
  return analysis.coverage;
}

function requireHealth(analysis: AnalysisResult): NonNullable<AnalysisResult["analysisHealth"]> {
  if (!analysis.analysisHealth) throw new Error("Analysis did not record health.");
  return analysis.analysisHealth;
}

export function recordedDecision(analysis: AnalysisResult): "allow" | "warn" | "block" {
  const decisions = analysis.decisions ?? [];
  if (decisions.some((item) => item.type === "block")) return "block";
  if (decisions.some((item) => item.type === "warn")) return "warn";
  return "allow";
}

async function writeBoundedFile(path: string, bytes: Uint8Array): Promise<void> {
  const directory = dirname(path);
  await ensureStageDirectory(directory);
  const handle = await open(path, "wx", 0o600);
  try {
    await handle.writeFile(bytes);
  } finally {
    await handle.close();
  }
}

async function ensureStageDirectory(directory: string): Promise<void> {
  if (process.env.GITHUB_ACTIONS !== "true" || !process.env.RUNNER_TEMP) {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const metadata = await lstat(directory);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new Error("Stage artifact directories must be regular directories, not symlinks.");
    }
    return;
  }

  const trustedRoot = resolve(process.env.RUNNER_TEMP);
  const rel = relative(trustedRoot, resolve(directory));
  if (!rel || rel === ".." || rel.startsWith("../") || rel.startsWith("..\\")) {
    throw new Error("Stage artifact directory escaped the trusted runner temporary directory.");
  }
  const rootMetadata = await lstat(trustedRoot);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    throw new Error("The trusted runner temporary directory is not a regular directory.");
  }

  let current = trustedRoot;
  for (const segment of rel.split(/[\\/]+/)) {
    current = resolve(current, segment);
    try {
      const metadata = await lstat(current);
      if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
        throw new Error("Stage artifact directories must be regular directories, not symlinks.");
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      try {
        await mkdir(current, { mode: 0o700 });
      } catch (creationError) {
        if ((creationError as NodeJS.ErrnoException).code !== "EEXIST") throw creationError;
      }
      const created = await lstat(current);
      if (!created.isDirectory() || created.isSymbolicLink()) {
        throw new Error("Stage artifact directories must be regular directories, not symlinks.");
      }
    }
  }
}
