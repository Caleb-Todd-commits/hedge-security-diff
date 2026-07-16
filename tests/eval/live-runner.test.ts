import { cp, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import type { AnalysisResult } from "../../src/domain/schemas.js";
import { containsInstructionLikeContent } from "../../src/security/untrusted.js";
import {
  DEFAULT_LIVE_EVAL_REPEATS,
  LiveEvalExecutionError,
  authorizeLiveEval,
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
    triageInputTokens: null,
    triageOutputTokens: null,
    analysisInputTokens: null,
    analysisOutputTokens: null
  };
}
