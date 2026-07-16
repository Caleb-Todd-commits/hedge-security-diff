import { cp, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  AnalysisResult,
  AttackSurfaceGraph,
  Coverage,
  GraphDelta,
  SurfaceEdge,
  SurfaceNode
} from "../../src/domain/schemas.js";

const openAIMock = vi.hoisted(() => ({ parse: vi.fn() }));

vi.mock("openai", () => ({
  default: class MockOpenAI {
    readonly responses = { parse: openAIMock.parse };
  }
}));

import { HedgeConfigSchema } from "../../src/domain/schemas.js";
import { containsInstructionLikeContent } from "../../src/security/untrusted.js";
import {
  DEFAULT_LIVE_EVAL_REPEATS,
  LiveEvalExecutionError,
  authorizeLiveEval,
  createOpenAiLiveModelRunner,
  noDeltaStatusForCoverage,
  parseLiveEvalRepeats,
  runLiveEvalSuite,
  writeLiveEvalResults,
  type LiveModelExecution,
  type LiveModelRequest,
  type LiveModelRunner
} from "../../src/eval/live-runner.js";

const fixturesRoot = resolve("eval/heldout-fixtures");
const caseConfigPath = resolve("eval/live-eval-cases.json");

describe("API-backed live evaluation", () => {
  beforeEach(() => {
    openAIMock.parse.mockReset();
  });

  it("requires explicit opt-in and an API key while refusing GitHub credentials", () => {
    expect(() => authorizeLiveEval({ OPENAI_API_KEY: "sk-test-credential-value" })).toThrow(
      "HEDGE_LIVE_EVAL=1"
    );
    expect(() => authorizeLiveEval({ HEDGE_LIVE_EVAL: "1" })).toThrow("OPENAI_API_KEY");
    expect(() =>
      authorizeLiveEval({
        HEDGE_LIVE_EVAL: "1",
        OPENAI_API_KEY: "sk-test-credential-value",
        GITHUB_TOKEN: "github-token-value"
      })
    ).toThrow("refuses GitHub credentials");
    expect(() =>
      authorizeLiveEval({
        HEDGE_LIVE_EVAL: "1",
        OPENAI_API_KEY: "sk-test-credential-value",
        ACTIONS_RUNTIME_TOKEN: "actions-token-value"
      })
    ).toThrow("ACTIONS_RUNTIME_TOKEN");
    expect(parseLiveEvalRepeats(undefined)).toBe(DEFAULT_LIVE_EVAL_REPEATS);
    expect(parseLiveEvalRepeats("4")).toBe(4);
    expect(() => parseLiveEvalRepeats("6")).toThrow("between 1 and 5");
    expect(noDeltaStatusForCoverage("complete")).toBe("confirmed-no-delta");
    expect(noDeltaStatusForCoverage("partial")).toBe("unconfirmed-no-delta");
    expect(noDeltaStatusForCoverage("unsupported")).toBe("unconfirmed-no-delta");
  });

  it("runs exactly ten frozen held-out pairs and aggregates routing, stability, and provenance", async () => {
    const callsByRepository = new Map<string, number>();
    let boundaryProbeCalls = 0;
    const runner: LiveModelRunner = {
      async run(request) {
        const repository = request.graph.repository;
        const call = (callsByRepository.get(repository) ?? 0) + 1;
        callsByRepository.set(repository, call);
        if (repository.endsWith("110-integration-boundary-probe")) {
          expect(containsInstructionLikeContent(request.patch)).toBe(true);
          boundaryProbeCalls += 1;
        }
        const variable = repository.endsWith("107-link-preview-outbound") && call === 2;
        return fakeExecution(request, variable ? "block" : "warn");
      }
    };

    const summary = await runLiveEvalSuite({
      fixturesRoot,
      caseConfigPath,
      runner,
      repeats: 2,
      now: () => new Date("2026-07-19T12:00:00.000Z")
    });

    expect(summary.casesConfigured).toBe(10);
    expect(summary.corpusClassification).toBe("frozen-held-out");
    expect(summary.heldOutGateCompleted).toBe(true);
    expect(summary.frozenAt).toBe("2026-07-16T14:53:15.000Z");
    expect(summary.corpusDigest).toBe(
      "4da85338c82db9e6fdd595831be7b33389625862fbd26e79ddc4ffbb6797edfd"
    );
    expect(summary.requestedRuns).toBe(20);
    expect(summary.recordedRuns).toBe(20);
    expect(summary.generatedAt).toBe("2026-07-19T12:00:00.000Z");
    expect(summary.aggregate.rejectedModelProposals).toBeGreaterThan(0);
    expect(summary.aggregate.exactEvidenceValidityRate).toBe(1);
    expect(summary.aggregate.inputTokens.samples).toBeGreaterThan(0);
    expect(summary.aggregate.inputTokens.median).toBe(12);
    expect(summary.aggregate.totalTokens.median).toBe(17);
    expect(summary.aggregate.reasoningTokens.median).toBe(2);
    expect(summary.aggregate.modelCalls).toBeGreaterThan(0);
    expect(summary.cases.every((item) => item.provenance.patchBytes <= 60_000)).toBe(true);
    expect(
      summary.cases.every(
        (item) =>
          /^[a-f0-9]{64}$/.test(item.provenance.baseSha) &&
          /^[a-f0-9]{64}$/.test(item.provenance.headSha) &&
          /^[a-f0-9]{64}$/.test(item.provenance.fixtureDigest) &&
          item.provenance.corpusDigest === summary.corpusDigest
      )
    ).toBe(true);
    expect(summary.cases.every((item) => item.findingStability.stable)).toBe(true);
    expect(boundaryProbeCalls).toBe(2);
    expect(summary.boundaryProbeCases).toEqual(["110-integration-boundary-probe"]);
    expect(
      summary.cases.find((item) => item.id === "110-integration-boundary-probe")?.provenance
        .boundaryProbe
    ).toBe(true);
    expect(
      summary.cases.find((item) => item.id === "110-integration-boundary-probe")?.architectureDelta
    ).toBe(true);
    expect(
      summary.cases.find((item) => item.id === "107-link-preview-outbound")
        ?.recordedDecisionStability.stable
    ).toBe(false);

    const benign = summary.cases.find((item) => item.id === "101-benign-clock-refactor");
    expect(benign?.runs.every((run) => run.routing.path === "no-model")).toBe(true);
    expect(benign?.runs.every((run) => run.status === "confirmed-no-delta")).toBe(true);

    const unknown = summary.cases.find((item) => item.id === "109-unresolved-billing-control");
    expect(unknown?.coverage.comparison).toBe("partial");
  });

  it("keeps the held-out directory separate and rejects fixture tampering before model work", async () => {
    const [heldOutNames, developmentNames] = await Promise.all([
      readdir(fixturesRoot),
      readdir(resolve("eval/fixtures"))
    ]);
    expect(heldOutNames).toHaveLength(10);
    expect(heldOutNames.some((name) => developmentNames.includes(name))).toBe(false);

    let calls = 0;
    const runner: LiveModelRunner = {
      async run(request) {
        calls += 1;
        return fakeExecution(request, "warn");
      }
    };
    await expect(
      runLiveEvalSuite({
        fixturesRoot: resolve("eval/fixtures"),
        caseConfigPath,
        runner,
        repeats: 1
      })
    ).rejects.toThrow("separate heldout-fixtures directory");

    const temporaryRoot = await mkdtemp(join(tmpdir(), "hedge-heldout-tamper-"));
    const copiedFixtures = join(temporaryRoot, "heldout-fixtures");
    await cp(fixturesRoot, copiedFixtures, { recursive: true });
    const changedFile = join(
      copiedFixtures,
      "101-benign-clock-refactor",
      "after",
      "app/api/clock/route.ts"
    );
    await writeFile(
      changedFile,
      `${await readFile(changedFile, "utf8")}\n// changed after freeze\n`
    );
    await expect(
      runLiveEvalSuite({
        fixturesRoot: copiedFixtures,
        caseConfigPath,
        runner,
        repeats: 1
      })
    ).rejects.toThrow("fixture digest mismatch for 101-benign-clock-refactor");
    expect(calls).toBe(0);
  });

  it("fails closed and stops issuing model requests after a boundary failure", async () => {
    let calls = 0;
    const runner: LiveModelRunner = {
      async run(request) {
        calls += 1;
        throw new LiveEvalExecutionError(
          "raw model text must not be recorded",
          "analysis-boundary",
          true,
          {
            triageModel: request.config.models.triage,
            analysisModel: request.config.models.analysis,
            triageCalled: true,
            triageRequestedDeepAnalysis: true,
            deterministicDeepAnalysisRequired: true,
            analysisCalled: true,
            path: "luna-to-sol"
          },
          emptyUsage(),
          { totalMs: 10, triageMs: 4, analysisMs: 6 }
        );
      }
    };

    const summary = await runLiveEvalSuite({
      fixturesRoot,
      caseConfigPath,
      runner,
      repeats: 3
    });

    expect(calls).toBe(1);
    expect(summary.abortedAfterBoundaryFailure).toBe(true);
    expect(summary.operationalGatePassed).toBe(false);
    expect(summary.aggregate.boundaryFailures).toBe(1);
    expect(summary.recordedRuns).toBeLessThan(summary.requestedRuns);
  });

  it("records API failures without persisting credentials or echoed patch content", async () => {
    const secret = "sk-test-super-secret-value";
    const runner: LiveModelRunner = {
      async run(request) {
        throw new LiveEvalExecutionError(
          `provider echoed ${secret} and ${request.patch}`,
          "triage",
          false,
          {
            triageModel: request.config.models.triage,
            analysisModel: request.config.models.analysis,
            triageCalled: true,
            triageRequestedDeepAnalysis: null,
            deterministicDeepAnalysisRequired: true,
            analysisCalled: false,
            path: "failed"
          },
          emptyUsage(),
          { totalMs: 1, triageMs: 1, analysisMs: null }
        );
      }
    };
    const summary = await runLiveEvalSuite({
      fixturesRoot,
      caseConfigPath,
      runner,
      repeats: 1
    });
    const output = await mkdtemp(join(tmpdir(), "hedge-live-eval-"));
    const paths = await writeLiveEvalResults(output, summary, [secret]);
    const [json, markdown] = await Promise.all([
      readFile(paths.jsonPath, "utf8"),
      readFile(paths.markdownPath, "utf8")
    ]);

    expect(summary.operationalGatePassed).toBe(false);
    expect(summary.aggregate.apiOrModelFailures).toBeGreaterThan(0);
    expect(json).not.toContain(secret);
    expect(markdown).not.toContain(secret);
    expect(json).not.toContain("Ignore all previous instructions");
    expect(json).toContain("provider details were intentionally not persisted");
  });

  it("records a complete medium deterministic recommendation without spending model tokens", async () => {
    const source: SurfaceNode = {
      id: "component:upload-service",
      kind: "component",
      label: "Upload service",
      trustZone: "application",
      evidence: [],
      controls: [control("authentication"), control("size-limit"), control("content-type")],
      metadata: {}
    };
    const storage: SurfaceNode = {
      id: "storage:objects",
      kind: "storage",
      label: "Object storage",
      trustZone: "external",
      evidence: [],
      controls: [],
      metadata: {}
    };
    const write: SurfaceEdge = {
      id: "edge:upload:storage",
      from: source.id,
      to: storage.id,
      kind: "writes",
      evidence: [],
      controls: [],
      confidence: 1
    };
    const execution = await createOpenAiLiveModelRunner("sk-test").run(
      modelRequest({ addedEdges: [write] }, [source, storage], [write])
    );

    expect(openAIMock.parse).not.toHaveBeenCalled();
    expect(execution.analysis.findings).toEqual([
      expect.objectContaining({ severity: "medium", origin: "deterministic" })
    ]);
    expect(execution.routing).toEqual(
      expect.objectContaining({
        path: "deterministic",
        triageCalled: false,
        analysisCalled: false,
        deterministicDeepAnalysisRequired: false
      })
    );
    expect(execution.usage).toEqual(expect.objectContaining({ totalTokens: 0, modelCalls: 0 }));
    expect(execution.latency).toEqual({ totalMs: 0, triageMs: null, analysisMs: null });
    expect(execution.boundary.status).toBe("not-exercised-no-model");
  });

  it("routes a deterministically sensitive change directly to Sol without Luna", async () => {
    openAIMock.parse.mockResolvedValueOnce(
      completedResponse(
        {
          findings: [],
          integrity: {
            untrustedInstructionsObserved: false,
            analysisBoundaryHeld: true
          }
        },
        usage(600, 90, 40)
      )
    );
    const entrypoint: SurfaceNode = {
      id: "entrypoint:public-write",
      kind: "entrypoint",
      label: "POST /api/public-write",
      trustZone: "public",
      evidence: [],
      controls: [],
      metadata: { method: "POST" }
    };

    const execution = await createOpenAiLiveModelRunner("sk-test").run(
      modelRequest({ addedNodes: [entrypoint] }, [entrypoint])
    );

    expect(openAIMock.parse).toHaveBeenCalledTimes(1);
    expect(openAIMock.parse).toHaveBeenCalledWith(
      expect.objectContaining({ model: "gpt-5.6-sol" })
    );
    expect(execution.routing).toEqual(
      expect.objectContaining({
        path: "sol-direct",
        triageCalled: false,
        triageRequestedDeepAnalysis: null,
        deterministicDeepAnalysisRequired: true,
        analysisCalled: true
      })
    );
    expect(execution.analysis.findings).toEqual([
      expect.objectContaining({ severity: "high", origin: "deterministic" })
    ]);
    expect(execution.usage).toEqual(
      expect.objectContaining({
        inputTokens: 600,
        outputTokens: 90,
        totalTokens: 690,
        reasoningTokens: 40,
        modelCalls: 1,
        triageInputTokens: null,
        analysisInputTokens: 600
      })
    );
    expect(execution.latency.triageMs).toBeNull();
    expect(execution.latency.analysisMs).not.toBeNull();
    expect(execution.latency.totalMs).toBe(execution.latency.analysisMs);
  });

  it("uses Luna for ambiguous changes and calls Sol only when Luna requests it", async () => {
    const dependency: SurfaceNode = {
      id: "dependency:utility",
      kind: "dependency",
      label: "utility@2.0.0",
      trustZone: "external",
      evidence: [],
      controls: [],
      metadata: {}
    };
    const request = modelRequest({ addedNodes: [dependency] }, [dependency]);
    openAIMock.parse.mockResolvedValueOnce(
      completedResponse({ deepAnalysisRequired: false }, usage(100, 12, 2))
    );

    const lunaOnly = await createOpenAiLiveModelRunner("sk-test").run(request);

    expect(lunaOnly.routing.path).toBe("luna-only");
    expect(lunaOnly.routing.analysisCalled).toBe(false);
    expect(lunaOnly.usage).toEqual(
      expect.objectContaining({ totalTokens: 112, modelCalls: 1, analysisInputTokens: null })
    );

    openAIMock.parse
      .mockResolvedValueOnce(completedResponse({ deepAnalysisRequired: true }, usage(110, 14, 3)))
      .mockResolvedValueOnce(
        completedResponse(
          {
            findings: [],
            integrity: {
              untrustedInstructionsObserved: false,
              analysisBoundaryHeld: true
            }
          },
          usage(500, 80, 30)
        )
      );

    const lunaToSol = await createOpenAiLiveModelRunner("sk-test").run(request);

    expect(lunaToSol.routing.path).toBe("luna-to-sol");
    expect(lunaToSol.routing.triageRequestedDeepAnalysis).toBe(true);
    expect(lunaToSol.usage).toEqual(
      expect.objectContaining({
        inputTokens: 610,
        outputTokens: 94,
        totalTokens: 704,
        reasoningTokens: 33,
        modelCalls: 2,
        triageInputTokens: 110,
        analysisInputTokens: 500
      })
    );
    expect(lunaToSol.latency.triageMs).not.toBeNull();
    expect(lunaToSol.latency.analysisMs).not.toBeNull();
  });
});

function fakeExecution(
  request: LiveModelRequest,
  decisionType: "warn" | "block"
): LiveModelExecution {
  const analysis: AnalysisResult = {
    summary: "Synthetic fake-runner result.",
    surfaceChanged: true,
    confirmedNoDelta: false,
    coverage: request.coverage,
    analysisHealth: { status: "complete", reasons: [] },
    findings: [],
    integrity: {
      untrustedInstructionsObserved: false,
      analysisBoundaryHeld: true,
      notes: []
    },
    limitations: [],
    model: request.config.models.analysis,
    decisions: [
      {
        id: `decision-${decisionType}`,
        type: decisionType,
        reason: "Fixed fake-runner decision.",
        source: "threshold",
        riskFingerprints: [],
        invariantIds: [],
        observationIds: [],
        inferenceIds: []
      }
    ]
  };
  return {
    analysis,
    routing: {
      triageModel: request.config.models.triage,
      analysisModel: request.config.models.analysis,
      triageCalled: true,
      triageRequestedDeepAnalysis: true,
      deterministicDeepAnalysisRequired: true,
      analysisCalled: true,
      path: "luna-to-sol"
    },
    exactEvidence: {
      valid: true,
      acceptedModelFindings: 0,
      acceptedEvidenceReferences: 0,
      rejectedProposals: 1,
      invalidModelFindings: 0
    },
    usage: {
      inputTokens: 12,
      outputTokens: 5,
      totalTokens: 17,
      cachedInputTokens: 0,
      reasoningTokens: 2,
      modelCalls: 2,
      triageInputTokens: 4,
      triageOutputTokens: 1,
      analysisInputTokens: 8,
      analysisOutputTokens: 4
    },
    latency: { totalMs: 25, triageMs: 5, analysisMs: 20 },
    boundary: {
      instructionLikeContentObserved: containsInstructionLikeContent(request.patch),
      analysisBoundaryHeld: true,
      status: "held"
    }
  };
}

function emptyUsage() {
  return {
    inputTokens: null,
    outputTokens: null,
    totalTokens: null,
    cachedInputTokens: null,
    reasoningTokens: null,
    modelCalls: 0,
    triageInputTokens: null,
    triageOutputTokens: null,
    analysisInputTokens: null,
    analysisOutputTokens: null
  };
}

const completeCoverage: Coverage = {
  status: "complete",
  discoveredFiles: 1,
  includedFiles: 1,
  includedBytes: 1,
  omitted: { fileLimit: 0, byteLimit: 0, unsafeOrUnreadable: 0, binary: 0 },
  diagnostics: []
};

const emptyDelta: GraphDelta = {
  addedNodes: [],
  removedNodes: [],
  changedNodes: [],
  addedEdges: [],
  removedEdges: [],
  changedEdges: []
};

function modelRequest(
  delta: Partial<GraphDelta>,
  nodes: SurfaceNode[],
  edges: SurfaceEdge[] = []
): LiveModelRequest {
  const headSha = "a".repeat(64);
  const graph: AttackSurfaceGraph = {
    schemaVersion: "0.1",
    generatedAt: new Date(0).toISOString(),
    repository: "live-eval/routing-test",
    sourceCommit: headSha,
    framework: "nextjs",
    nodes,
    edges,
    assumptions: [],
    unknowns: [],
    coverage: completeCoverage
  };
  return {
    graph,
    delta: { ...emptyDelta, ...delta },
    patch: "synthetic bounded patch",
    config: HedgeConfigSchema.parse({ framework: "nextjs", fail_on: "high" }),
    headSha,
    coverage: completeCoverage
  };
}

function control(type: "authentication" | "size-limit" | "content-type") {
  return {
    type,
    label: `Confirmed ${type}`,
    evidence: [],
    confidence: 1,
    assurance: "confirmed" as const
  };
}

function usage(inputTokens: number, outputTokens: number, reasoningTokens: number) {
  return {
    input_tokens: inputTokens,
    output_tokens: outputTokens,
    total_tokens: inputTokens + outputTokens,
    input_tokens_details: { cached_tokens: 0 },
    output_tokens_details: { reasoning_tokens: reasoningTokens }
  };
}

function completedResponse(outputParsed: unknown, responseUsage: ReturnType<typeof usage>) {
  return {
    status: "completed",
    incomplete_details: null,
    output_parsed: outputParsed,
    usage: responseUsage
  };
}
