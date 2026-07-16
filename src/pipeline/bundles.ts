import { z } from "zod";
import {
  CollectionBundleSchema,
  ReasonBundleSchema,
  type CollectionBundle,
  type Evidence,
  type ReasonBundle
} from "../domain/schemas.js";
import { diffGraphs, hasSecurityArchitectureDelta } from "../graph/diff.js";
import { stableHash, stableStringify } from "../utils/hash.js";
import { analyzeSecurityInvariants } from "../analysis/invariants.js";
import { analyzeWithHeuristics } from "../analysis/heuristics.js";
import { analyzeWithCustomPolicies } from "../analysis/policies.js";
import { buildInferences, buildObservations } from "../analysis/observations.js";
import { buildDecisions } from "../analysis/decisions.js";
import { emptyRegister, markMissingFindingsAsMitigated, mergeFindings } from "../register/store.js";

const MAX_BUNDLE_BYTES = 4 * 1024 * 1024;
const StrictCollectionBundleSchema = CollectionBundleSchema.strict();
const StrictReasonBundleSchema = ReasonBundleSchema.strict();

export interface PipelineBindings {
  repository: string;
  pullRequest: number;
  baseSha: string;
  headSha: string;
  workflowRef: string;
  actionVersion: string;
}

export function createCollectionBundle(
  input: z.input<typeof CollectionBundleSchema>
): CollectionBundle {
  const bundle = StrictCollectionBundleSchema.parse(input);
  validateCollectionSemantics(bundle);
  return bundle;
}

export function parseCollectionBundle(
  input: unknown,
  expected?: PipelineBindings
): CollectionBundle {
  const raw = parseBoundedJson(input, "collection bundle");
  const result = StrictCollectionBundleSchema.safeParse(raw);
  if (!result.success) {
    throw new Error(`Collection bundle schema validation failed: ${z.prettifyError(result.error)}`);
  }
  assertCanonical(raw, result.data, "Collection bundle");
  if (expected) verifyBindings(result.data, expected, "Collection bundle");
  validateCollectionSemantics(result.data);
  return result.data;
}

export function createReasonBundle(input: z.input<typeof ReasonBundleSchema>): ReasonBundle {
  return StrictReasonBundleSchema.parse(input);
}

export function parseReasonBundle(input: unknown, expected?: PipelineBindings): ReasonBundle {
  const raw = parseBoundedJson(input, "reason bundle");
  const result = StrictReasonBundleSchema.safeParse(raw);
  if (!result.success) {
    throw new Error(`Reason bundle schema validation failed: ${z.prettifyError(result.error)}`);
  }
  assertCanonical(raw, result.data, "Reason bundle");
  if (expected) verifyBindings(result.data, expected, "Reason bundle");
  return result.data;
}

export function serializePipelineBundle(value: CollectionBundle | ReasonBundle): Uint8Array {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
  if (bytes.byteLength > MAX_BUNDLE_BYTES) {
    throw new Error(`Pipeline bundle is ${bytes.byteLength} bytes; limit is ${MAX_BUNDLE_BYTES}.`);
  }
  return bytes;
}

export function verifyReasonAgainstCollection(
  reason: ReasonBundle,
  collection: CollectionBundle,
  collectionManifestDigest: string
): void {
  verifyBindings(reason, collection, "Reason bundle");
  if (reason.collectionManifestDigest !== collectionManifestDigest) {
    throw new Error("Reason bundle is not bound to the validated collection manifest.");
  }
  if (reason.analysis.surfaceChanged !== collection.analysis.surfaceChanged) {
    throw new Error("Reason bundle surface-change state disagrees with collection evidence.");
  }
  if (stableHash(reason.analysis.coverage, 64) !== stableHash(collection.coverage, 64)) {
    throw new Error("Reason bundle coverage does not match the collected evidence coverage.");
  }
  validateReasonEvidence(reason, collection);
  if (collection.analysis.surfaceChanged) validateReasonSemantics(reason, collection);
}

function validateReasonSemantics(reason: ReasonBundle, collection: CollectionBundle): void {
  const health = reason.analysis.analysisHealth;
  if (!health) throw new Error("Reason bundle did not record analysis health.");
  const healthRank = { complete: 0, degraded: 1, failed: 2 } as const;
  if (healthRank[health.status] < healthRank[collection.analysisHealth.status]) {
    throw new Error(
      "Reason bundle analysis health is healthier than the collected evidence permits."
    );
  }
  if (reason.analysis.confirmedNoDelta) {
    throw new Error("A changed architecture reason bundle cannot claim confirmed no-delta.");
  }

  const invariantAnalysis = analyzeSecurityInvariants(
    collection.delta,
    collection.config.invariants,
    { coverage: collection.coverage }
  );
  if (
    stableHash(reason.analysis.invariantEvaluations ?? [], 64) !==
    stableHash(invariantAnalysis.evaluations, 64)
  ) {
    throw new Error("Reason bundle invariant evaluations do not match deterministic analysis.");
  }

  validateDecisionEligibleFindings(reason, collection, invariantAnalysis.findings);

  const observations = buildObservations(collection.delta, invariantAnalysis.evaluations);
  const inferences = buildInferences(reason.analysis.findings, observations, reason.analysis.model);
  const decisions = buildDecisions(
    reason.analysis.findings,
    invariantAnalysis.evaluations,
    observations,
    inferences,
    collection.config.fail_on,
    health
  );
  const derivedLayers: Array<[unknown, unknown, string]> = [
    [reason.analysis.observations ?? [], observations, "observations"],
    [reason.analysis.inferences ?? [], inferences, "inferences"],
    [reason.analysis.decisions ?? [], decisions, "decisions"]
  ];
  for (const [actual, expected, label] of derivedLayers) {
    if (stableHash(actual, 64) !== stableHash(expected, 64)) {
      throw new Error(`Reason bundle ${label} do not match deterministic derivation.`);
    }
  }

  const register = structuredClone(collection.register ?? emptyRegister());
  const proposals = reason.analysis.findings.map((finding) => ({
    ...finding,
    id: "HEDGE-PENDING",
    status: "open" as const,
    verificationHistory: []
  }));
  const merged = mergeFindings(register, proposals);
  const lifecycleIdentity = (finding: (typeof reason.analysis.findings)[number]) => ({
    id: finding.id,
    fingerprint: finding.fingerprint,
    status: finding.status,
    origin: finding.origin,
    severity: finding.severity,
    evidence: finding.evidence
  });
  if (
    stableHash(reason.analysis.findings.map(lifecycleIdentity), 64) !==
    stableHash(merged.runFindings.map(lifecycleIdentity), 64)
  ) {
    throw new Error("Reason bundle finding IDs or lifecycle statuses do not match trusted state.");
  }
  const expectedLifecycle = markMissingFindingsAsMitigated(
    merged.register,
    merged.runFindings,
    collection.delta,
    {
      modelAnalysisCompleted: reason.analysis.model === collection.config.models.analysis,
      analysisComplete: health.status === "complete"
    }
  );
  if (
    stableHash(reason.lifecycleUpdates.map(lifecycleIdentity), 64) !==
    stableHash(expectedLifecycle.map(lifecycleIdentity), 64)
  ) {
    throw new Error("Reason bundle lifecycle updates do not match trusted deterministic state.");
  }
}

function validateDecisionEligibleFindings(
  reason: ReasonBundle,
  collection: CollectionBundle,
  invariantFindings: ReasonBundle["analysis"]["findings"]
): void {
  const expected = new Map(
    [
      ...analyzeWithHeuristics(collection.delta, collection.graph),
      ...analyzeWithCustomPolicies(collection.delta, collection.config.policies),
      ...invariantFindings
    ].map((finding) => [finding.fingerprint, finding])
  );
  const decisionEligibleOrigins = new Set(["deterministic", "policy", "invariant"]);
  for (const finding of reason.analysis.findings) {
    if (!decisionEligibleOrigins.has(finding.origin)) continue;
    const derived = expected.get(finding.fingerprint);
    if (
      !derived ||
      finding.origin !== derived.origin ||
      finding.severity !== derived.severity ||
      stableHash(finding.evidence, 64) !== stableHash(derived.evidence, 64)
    ) {
      throw new Error(
        `Reason bundle finding ${finding.id} is not an exact decision-eligible deterministic finding.`
      );
    }
  }
}

function validateReasonEvidence(reason: ReasonBundle, collection: CollectionBundle): void {
  const exactEvidence = new Set<string>();
  const addSubjectEvidence = (subject: {
    evidence: Evidence[];
    controls: Array<{ evidence: Evidence[] }>;
  }) => {
    for (const evidence of subject.evidence) exactEvidence.add(stableHash(evidence, 64));
    for (const control of subject.controls) {
      for (const evidence of control.evidence) exactEvidence.add(stableHash(evidence, 64));
    }
  };

  for (const node of collection.delta.addedNodes) addSubjectEvidence(node);
  for (const node of collection.delta.removedNodes) addSubjectEvidence(node);
  for (const pair of collection.delta.changedNodes) {
    addSubjectEvidence(pair.before);
    addSubjectEvidence(pair.after);
  }
  for (const edge of collection.delta.addedEdges) addSubjectEvidence(edge);
  for (const edge of collection.delta.removedEdges) addSubjectEvidence(edge);
  for (const pair of collection.delta.changedEdges) {
    addSubjectEvidence(pair.before);
    addSubjectEvidence(pair.after);
  }

  for (const finding of reason.analysis.findings) {
    if (!finding.evidence.length) {
      throw new Error(`Reason bundle finding ${finding.id} has no exact collected evidence.`);
    }
    for (const evidence of finding.evidence) {
      if (!exactEvidence.has(stableHash(evidence, 64))) {
        throw new Error(
          `Reason bundle finding ${finding.id} contains evidence that is not an exact collected provenance record.`
        );
      }
    }
  }
}

function validateCollectionSemantics(bundle: CollectionBundle): void {
  if (bundle.baseSha === bundle.headSha && bundle.analysis.surfaceChanged) {
    throw new Error("Identical base/head revisions cannot carry an architecture delta.");
  }
  if (bundle.baseline.sourceCommit !== bundle.baseSha) {
    throw new Error("Collection base graph is not bound to the exact base SHA.");
  }
  if (bundle.graph.sourceCommit !== bundle.headSha) {
    throw new Error("Collection head graph is not bound to the exact head SHA.");
  }
  const recomputedDelta = diffGraphs(bundle.baseline, bundle.graph);
  if (stableHash(recomputedDelta, 64) !== stableHash(bundle.delta, 64)) {
    throw new Error("Collection graph delta does not match the exact bound graphs.");
  }
  const surfaceChanged = hasSecurityArchitectureDelta(recomputedDelta);
  if (bundle.analysis.surfaceChanged !== surfaceChanged) {
    throw new Error("Collection analysis surface-change state disagrees with the graph delta.");
  }
  if (stableHash(bundle.analysis.coverage, 64) !== stableHash(bundle.coverage, 64)) {
    throw new Error("Collection analysis coverage disagrees with the bound coverage record.");
  }
  if (stableHash(bundle.analysis.analysisHealth, 64) !== stableHash(bundle.analysisHealth, 64)) {
    throw new Error("Collection analysis health disagrees with the bound health record.");
  }
  if (
    bundle.analysis.confirmedNoDelta &&
    (surfaceChanged ||
      bundle.coverage.status !== "complete" ||
      bundle.analysisHealth.status !== "complete")
  ) {
    throw new Error("Collection claims confirmed no-delta without complete exact evidence.");
  }
}

function verifyBindings(
  actual: Pick<
    CollectionBundle | ReasonBundle,
    "repository" | "pullRequest" | "baseSha" | "headSha" | "workflowRef" | "actionVersion"
  >,
  expected: PipelineBindings,
  label: string
): void {
  const fields: Array<[keyof PipelineBindings, string]> = [
    ["repository", "repository"],
    ["pullRequest", "pull request"],
    ["baseSha", "base SHA"],
    ["headSha", "head SHA"],
    ["workflowRef", "workflow"],
    ["actionVersion", "action version"]
  ];
  for (const [field, name] of fields) {
    if (actual[field] !== expected[field]) {
      throw new Error(`${label} ${name} binding does not match the authorized run.`);
    }
  }
}

function parseBoundedJson(input: unknown, label: string): unknown {
  if (typeof input !== "string" && !(input instanceof Uint8Array)) return input;
  const bytes = typeof input === "string" ? Buffer.from(input, "utf8") : Buffer.from(input);
  if (bytes.byteLength > MAX_BUNDLE_BYTES) {
    throw new Error(`${label} is ${bytes.byteLength} bytes; limit is ${MAX_BUNDLE_BYTES}.`);
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${label} is not valid UTF-8.`);
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
}

function assertCanonical(raw: unknown, parsed: unknown, label: string): void {
  if (stableStringify(raw) !== stableStringify(parsed)) {
    throw new Error(`${label} contains unknown, missing-default, or non-canonical fields.`);
  }
}
