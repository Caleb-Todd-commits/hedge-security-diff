import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AttackSurfaceGraph, GraphDelta } from "../../src/domain/schemas.js";

const openAIMock = vi.hoisted(() => ({
  constructorOptions: [] as unknown[],
  parse: vi.fn()
}));

vi.mock("openai", () => ({
  default: class MockOpenAI {
    readonly responses = { parse: openAIMock.parse };

    constructor(options: unknown) {
      openAIMock.constructorOptions.push(options);
    }
  }
}));

import { ModelRouter } from "../../src/model/client.js";
import { buildPromptEvidenceIndex } from "../../src/model/prompts.js";

const delta: GraphDelta = {
  addedNodes: [],
  removedNodes: [],
  changedNodes: [],
  addedEdges: [],
  removedEdges: [],
  changedEdges: []
};

const graph: AttackSurfaceGraph = {
  schemaVersion: "0.1",
  generatedAt: new Date(0).toISOString(),
  repository: "test/repo",
  framework: "nextjs",
  nodes: [],
  edges: [],
  assumptions: [],
  unknowns: []
};

describe("model request budgets", () => {
  beforeEach(() => {
    openAIMock.constructorOptions.length = 0;
    openAIMock.parse.mockReset();
  });

  it("uses a bounded, non-persistent, zero-retry triage request and records detailed usage", async () => {
    openAIMock.parse.mockResolvedValueOnce(
      completedResponse(
        { deepAnalysisRequired: false },
        {
          input_tokens: 120,
          output_tokens: 18,
          total_tokens: 138,
          input_tokens_details: { cached_tokens: 80 },
          output_tokens_details: { reasoning_tokens: 12 }
        }
      )
    );

    const result = await router().triage(delta, "");

    expect(openAIMock.constructorOptions).toEqual([
      expect.objectContaining({ maxRetries: 0, timeout: 90_000 })
    ]);
    expect(openAIMock.parse).toHaveBeenCalledWith(
      expect.objectContaining({
        model: "gpt-triage-test",
        max_output_tokens: 384,
        reasoning: { effort: "minimal" },
        store: false
      })
    );
    expect(result.usage).toEqual({
      inputTokens: 120,
      outputTokens: 18,
      totalTokens: 138,
      cachedInputTokens: 80,
      reasoningTokens: 12,
      modelCalls: 1
    });
  });

  it("uses a bounded low-effort deep-analysis request", async () => {
    openAIMock.parse.mockResolvedValueOnce(
      completedResponse(
        {
          findings: [],
          integrity: {
            untrustedInstructionsObserved: false,
            analysisBoundaryHeld: true
          }
        },
        {
          input_tokens: 600,
          output_tokens: 90,
          total_tokens: 690,
          input_tokens_details: { cached_tokens: 0 },
          output_tokens_details: { reasoning_tokens: 40 }
        }
      )
    );

    const result = await router().analyze(graph, delta, "");

    expect(openAIMock.parse).toHaveBeenCalledWith(
      expect.objectContaining({
        model: "gpt-analysis-test",
        max_output_tokens: 4_096,
        reasoning: { effort: "low" },
        store: false
      })
    );
    expect(result.usage).toEqual(
      expect.objectContaining({ totalTokens: 690, reasoningTokens: 40, modelCalls: 1 })
    );
  });

  it("rejects a response truncated by the output-token budget", async () => {
    openAIMock.parse.mockResolvedValueOnce({
      status: "incomplete",
      incomplete_details: { reason: "max_output_tokens" },
      output_parsed: null,
      usage: null
    });

    await expect(router().triage(delta, "")).rejects.toThrow(/output-token budget/i);
  });

  it("refuses an oversized prompt before making a model request", async () => {
    const oversizedDelta: GraphDelta = {
      ...delta,
      addedNodes: Array.from({ length: 1_000 }, (_, index) => ({
        id: `component:${index}`,
        kind: "component" as const,
        label: `Component ${index} ${"x".repeat(512)}`,
        trustZone: "application" as const,
        evidence: [],
        controls: [],
        metadata: {}
      }))
    };

    await expect(router().triage(oversizedDelta, "")).rejects.toThrow(/input budget/i);
    expect(openAIMock.parse).not.toHaveBeenCalled();
  });

  it("validates removed, before-state, and control evidence using the model-facing index", async () => {
    const removedNode = {
      id: "entrypoint:retired",
      kind: "entrypoint" as const,
      label: "POST /api/retired",
      trustZone: "public" as const,
      evidence: [{ file: "app/api/retired/route.ts", line: 1, extractor: "test" }],
      controls: [
        {
          type: "authorization" as const,
          label: "Retired admin guard",
          evidence: [{ file: "app/api/retired/route.ts", line: 2, extractor: "test" }],
          confidence: 1,
          assurance: "confirmed" as const
        }
      ],
      metadata: {}
    };
    const beforeNode = {
      ...removedNode,
      id: "entrypoint:changed",
      label: "POST /api/changed (before)",
      evidence: [{ file: "app/api/changed/route.ts", line: 3, extractor: "test" }],
      controls: []
    };
    const afterNode = {
      ...beforeNode,
      label: "POST /api/changed (after)",
      evidence: [{ file: "app/api/changed/route.ts", line: 8, extractor: "test" }]
    };
    const evidenceDelta: GraphDelta = {
      ...delta,
      removedNodes: [removedNode],
      changedNodes: [{ before: beforeNode, after: afterNode }]
    };
    const evidenceGraph: AttackSurfaceGraph = { ...graph, nodes: [afterNode] };
    const evidenceRefs = Object.keys(buildPromptEvidenceIndex(evidenceGraph, evidenceDelta)).filter(
      (reference) => reference.includes("/removed/") || reference.includes("/before/")
    );
    expect(evidenceRefs.some((reference) => reference.includes("/control/"))).toBe(true);

    openAIMock.parse.mockResolvedValueOnce(
      completedResponse(
        {
          findings: [
            {
              title: "Removed control leaves a changed route assumption",
              severity: "medium",
              stride: ["Elevation of Privilege"],
              cwe: [],
              asset: "Administrative operation",
              attackerCapability: "Reach the public route",
              entryPoint: removedNode.label,
              trustBoundary: "Public to application",
              precondition: "The retired route remains reachable elsewhere",
              attackPath: ["Reach the route", "Invoke the operation without the retired guard"],
              potentialImpact: "An administrative action could lack its intended guard.",
              existingControls: [],
              missingControls: ["Confirmed authorization"],
              securityInvariant: "Administrative actions require confirmed authorization.",
              evidenceRefs,
              confidence: 0.7,
              suggestedTest: null,
              remediationPrompt: null
            }
          ],
          integrity: {
            untrustedInstructionsObserved: false,
            analysisBoundaryHeld: true
          }
        },
        {
          input_tokens: 600,
          output_tokens: 180,
          total_tokens: 780,
          input_tokens_details: { cached_tokens: 0 },
          output_tokens_details: { reasoning_tokens: 30 }
        }
      )
    );

    const result = await router().analyze(evidenceGraph, evidenceDelta, "");

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.evidence.map((item) => item.file)).toEqual(
      expect.arrayContaining(["app/api/retired/route.ts", "app/api/changed/route.ts"])
    );
  });
});

function router(): ModelRouter {
  return new ModelRouter({
    apiKey: "test-key-not-a-secret",
    triageModel: "gpt-triage-test",
    analysisModel: "gpt-analysis-test"
  });
}

function completedResponse(outputParsed: unknown, usage: unknown): unknown {
  return {
    status: "completed",
    incomplete_details: null,
    output_parsed: outputParsed,
    usage
  };
}
