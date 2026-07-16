import { describe, expect, it } from "vitest";
import { HedgeConfigSchema, HedgeContextSchema } from "../../src/domain/schemas.js";
import { analyzeWithHeuristics } from "../../src/analysis/heuristics.js";
import { buildInferences, buildObservations } from "../../src/analysis/observations.js";
import { buildDecisions } from "../../src/analysis/decisions.js";
import {
  createCollectionBundle,
  createReasonBundle,
  parseCollectionBundle,
  parseReasonBundle,
  serializePipelineBundle,
  verifyReasonAgainstCollection
} from "../../src/pipeline/bundles.js";

const baseSha = "a".repeat(40);
const headSha = "b".repeat(40);
const bindings = {
  repository: "example/repository",
  pullRequest: 17,
  baseSha,
  headSha,
  workflowRef: "example/repository/.github/workflows/hedge.yml@refs/heads/main",
  actionVersion: "0.5.2"
};
const coverage = {
  status: "complete" as const,
  discoveredFiles: 2,
  includedFiles: 2,
  includedBytes: 200,
  omitted: { fileLimit: 0, byteLimit: 0, unsafeOrUnreadable: 0, binary: 0 },
  diagnostics: []
};
const health = { status: "complete" as const, reasons: [] };

function fixture() {
  const graph = (sourceCommit: string, snapshot: "base" | "head") => ({
    schemaVersion: "0.1" as const,
    generatedAt: "2026-07-16T00:00:00.000Z",
    repository: bindings.repository,
    sourceCommit,
    framework: "nextjs",
    nodes: [],
    edges: [],
    assumptions: [],
    unknowns: [],
    coverage: {
      ...coverage,
      discoveredFiles: 1,
      includedFiles: 1,
      includedBytes: 100,
      diagnostics: [] as Array<{
        code: string;
        phase: "analysis";
        message: string;
        snapshot: typeof snapshot;
      }>
    }
  });
  return createCollectionBundle({
    schemaVersion: "0.1",
    ...bindings,
    config: HedgeConfigSchema.parse({ framework: "nextjs" }),
    context: HedgeContextSchema.parse({}),
    baseline: graph(baseSha, "base"),
    graph: graph(headSha, "head"),
    delta: {
      addedNodes: [],
      removedNodes: [],
      changedNodes: [],
      addedEdges: [],
      removedEdges: [],
      changedEdges: []
    },
    patch: "",
    coverage,
    analysisHealth: health,
    exactRevisions: true,
    analysis: {
      summary: "No exact graph delta.",
      surfaceChanged: false,
      confirmedNoDelta: true,
      coverage,
      analysisHealth: health,
      observations: [],
      inferences: [],
      decisions: [],
      invariantEvaluations: [],
      findings: [],
      integrity: {
        untrustedInstructionsObserved: false,
        analysisBoundaryHeld: true,
        notes: ["No model call was made."]
      },
      limitations: [],
      model: "none"
    }
  });
}

describe("staged pipeline bundles", () => {
  it("round-trips a canonical exact collection", () => {
    const bundle = fixture();
    expect(parseCollectionBundle(serializePipelineBundle(bundle), bindings)).toEqual(bundle);
  });

  it("rejects unknown nested fields and a delta that disagrees with the graphs", () => {
    const bundle = fixture();
    const unknown = JSON.parse(Buffer.from(serializePipelineBundle(bundle)).toString("utf8"));
    unknown.config.injected = true;
    expect(() => parseCollectionBundle(JSON.stringify(unknown), bindings)).toThrow(
      /non-canonical/i
    );

    const tampered = JSON.parse(Buffer.from(serializePipelineBundle(bundle)).toString("utf8"));
    tampered.delta.addedNodes.push({
      id: "entrypoint:tampered",
      kind: "entrypoint",
      label: "GET /tampered",
      trustZone: "public",
      evidence: [],
      controls: [],
      metadata: {}
    });
    expect(() => parseCollectionBundle(JSON.stringify(tampered), bindings)).toThrow(
      /does not match the exact bound graphs/i
    );
  });

  it("binds reasoning to the validated collection manifest", () => {
    const collection = fixture();
    const digest = "c".repeat(64);
    const reason = createReasonBundle({
      schemaVersion: "0.1",
      ...bindings,
      collectionManifestDigest: digest,
      analysis: collection.analysis,
      lifecycleUpdates: []
    });
    const parsed = parseReasonBundle(serializePipelineBundle(reason), bindings);
    expect(() => verifyReasonAgainstCollection(parsed, collection, digest)).not.toThrow();
    expect(() => verifyReasonAgainstCollection(parsed, collection, "d".repeat(64))).toThrow(
      /not bound/i
    );
  });

  it("rejects a valid subject id paired with fabricated evidence provenance", () => {
    const empty = fixture();
    const evidence = {
      file: "app/api/files/route.ts",
      line: 1,
      extractor: "nextjs-ast-route",
      commit: headSha,
      snapshot: "head" as const,
      subjectId: "entrypoint:files"
    };
    const node = {
      id: "entrypoint:files",
      kind: "entrypoint" as const,
      label: "POST /api/files",
      trustZone: "public" as const,
      evidence: [evidence],
      controls: [],
      metadata: { method: "POST" }
    };
    const graph = { ...empty.graph, nodes: [node] };
    const delta = { ...empty.delta, addedNodes: [node] };
    const findings = analyzeWithHeuristics(delta, graph).map((finding) => ({
      ...finding,
      id: "HEDGE-001"
    }));
    const observations = buildObservations(delta, []);
    const inferences = buildInferences(findings, observations, "deterministic-only");
    const decisions = buildDecisions(
      findings,
      [],
      observations,
      inferences,
      empty.config.fail_on,
      health
    );
    const collection = createCollectionBundle({
      ...empty,
      graph,
      delta,
      analysis: {
        ...empty.analysis,
        summary: "A mutating route was added.",
        surfaceChanged: true,
        confirmedNoDelta: false,
        findings,
        observations,
        inferences,
        decisions,
        model: "deterministic-only"
      }
    });
    const digest = "c".repeat(64);
    const reason = createReasonBundle({
      schemaVersion: "0.1",
      ...bindings,
      collectionManifestDigest: digest,
      analysis: collection.analysis,
      lifecycleUpdates: []
    });
    expect(() => verifyReasonAgainstCollection(reason, collection, digest)).not.toThrow();

    const fabricated = structuredClone(reason);
    fabricated.analysis.findings[0]!.evidence[0]!.file = "app/api/fabricated/route.ts";
    expect(() => verifyReasonAgainstCollection(fabricated, collection, digest)).toThrow(
      /exact collected provenance/i
    );

    const decisionTampering = structuredClone(reason);
    decisionTampering.analysis.decisions![0]!.type = "allow";
    expect(() => verifyReasonAgainstCollection(decisionTampering, collection, digest)).toThrow(
      /decisions do not match deterministic derivation/i
    );

    const healthTampering = structuredClone(reason);
    collection.analysisHealth = { status: "degraded", reasons: ["partial source evidence"] };
    collection.analysis.analysisHealth = collection.analysisHealth;
    healthTampering.analysis.analysisHealth = { status: "complete", reasons: [] };
    expect(() => verifyReasonAgainstCollection(healthTampering, collection, digest)).toThrow(
      /healthier than the collected evidence permits/i
    );
  });
});
