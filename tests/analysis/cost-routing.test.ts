import { describe, expect, it } from "vitest";
import { runAnalysis } from "../../src/analysis/run.js";
import { HedgeConfigSchema } from "../../src/domain/schemas.js";
import type {
  AttackSurfaceGraph,
  GraphDelta,
  SurfaceEdge,
  SurfaceNode
} from "../../src/domain/schemas.js";
import type { ModelRunResult, ModelUsage, TriageRunResult } from "../../src/model/client.js";

const config = HedgeConfigSchema.parse({ fail_on: "high" });
const evidence = [{ file: "src/service.ts", line: 1, extractor: "test" }];

const publicEntry: SurfaceNode = {
  id: "entrypoint:public",
  kind: "entrypoint",
  label: "GET /api/proxy",
  trustZone: "public",
  evidence,
  controls: [],
  metadata: { method: "GET" }
};

const dynamicService: SurfaceNode = {
  id: "external:dynamic",
  kind: "external-service",
  label: "Dynamic upstream",
  trustZone: "external",
  evidence,
  controls: [],
  metadata: { destination: "dynamic", userControlledHost: true }
};

const genericComponent: SurfaceNode = {
  id: "component:service",
  kind: "component",
  label: "Service",
  trustZone: "application",
  evidence,
  controls: [],
  metadata: {}
};

const dependency: SurfaceNode = {
  id: "dependency:utility",
  kind: "dependency",
  label: "utility@1.0.0",
  trustZone: "external",
  evidence,
  controls: [],
  metadata: {}
};

const dynamicCall: SurfaceEdge = {
  id: "edge:public:dynamic",
  from: publicEntry.id,
  to: dynamicService.id,
  kind: "calls",
  evidence,
  controls: [],
  confidence: 1
};

const genericCall: SurfaceEdge = {
  id: "edge:service:utility",
  from: genericComponent.id,
  to: dependency.id,
  kind: "calls",
  evidence,
  controls: [],
  confidence: 1
};

const mediumDelta = delta({ addedEdges: [dynamicCall] });
const mediumGraph = graph([publicEntry, dynamicService], [dynamicCall]);
const genericDelta = delta({ addedNodes: [genericComponent], addedEdges: [genericCall] });
const genericGraph = graph([genericComponent, dependency], [genericCall]);

describe("cost-aware model routing", () => {
  it("uses a medium deterministic recommendation without spending model tokens", async () => {
    const result = await runAnalysis({
      graph: mediumGraph,
      delta: mediumDelta,
      patch: "",
      config,
      recordedModel: {
        triage: { ...triage(true), model: "UNUSED TRIAGE MODEL" },
        analysis: analysis("UNUSED ANALYSIS PROSE", { inputTokens: 99, modelCalls: 1 })
      }
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.severity).toBe("medium");
    expect(result.modelRoute).toBe("deterministic");
    expect(result.model).toBe("deterministic-only");
    expect(result.usage).toBeUndefined();
    expect(JSON.stringify(result)).not.toContain("UNUSED");
  });

  it("skips triage and uses only recorded analysis for a sensitive high-severity path", async () => {
    const highEntry: SurfaceNode = {
      ...publicEntry,
      id: "entrypoint:admin",
      label: "POST /api/admin/users",
      metadata: { method: "POST" }
    };
    const analysisUsage: ModelUsage = {
      inputTokens: 20,
      outputTokens: 5,
      totalTokens: 25,
      cachedInputTokens: 4,
      reasoningTokens: 2,
      modelCalls: 1
    };
    const result = await runAnalysis({
      graph: graph([highEntry]),
      delta: delta({ addedNodes: [highEntry] }),
      patch: "",
      config,
      recordedModel: {
        triage: {
          ...triage(false),
          model: "UNUSED TRIAGE MODEL",
          usage: { inputTokens: 999, modelCalls: 1 }
        },
        analysis: analysis("RECORDED ANALYSIS PROSE", analysisUsage)
      }
    });

    expect(result.findings.some((finding) => finding.severity === "high")).toBe(true);
    expect(result.modelRoute).toBe("analysis");
    expect(result.model).toBe("recorded-analysis");
    expect(result.usage).toEqual(analysisUsage);
    expect(JSON.stringify(result)).not.toContain("UNUSED TRIAGE MODEL");
  });

  it("stops after low-cost triage when Luna does not request deep analysis", async () => {
    const triageUsage: ModelUsage = {
      inputTokens: 10,
      outputTokens: 2,
      totalTokens: 12,
      cachedInputTokens: 3,
      reasoningTokens: 1,
      modelCalls: 1
    };
    const result = await runAnalysis({
      graph: genericGraph,
      delta: genericDelta,
      patch: "",
      config,
      recordedModel: {
        triage: { ...triage(false), usage: triageUsage },
        analysis: analysis("UNUSED ANALYSIS PROSE", { inputTokens: 999, modelCalls: 1 })
      }
    });

    expect(result.findings).toEqual([]);
    expect(result.modelRoute).toBe("triage");
    expect(result.model).toBe("recorded-triage");
    expect(result.usage).toEqual(triageUsage);
    expect(JSON.stringify(result)).not.toContain("UNUSED ANALYSIS");
  });

  it("runs deep analysis after Luna requests it and sums every usage metric", async () => {
    const result = await runAnalysis({
      graph: genericGraph,
      delta: genericDelta,
      patch: "",
      config,
      recordedModel: {
        triage: {
          ...triage(true),
          usage: {
            inputTokens: 10,
            outputTokens: 2,
            totalTokens: 12,
            cachedInputTokens: 3,
            reasoningTokens: 1,
            modelCalls: 1
          }
        },
        analysis: analysis("Recorded deep analysis", {
          inputTokens: 20,
          outputTokens: 5,
          totalTokens: 25,
          cachedInputTokens: 4,
          reasoningTokens: 2,
          modelCalls: 1
        })
      }
    });

    expect(result.modelRoute).toBe("triage-analysis");
    expect(result.model).toBe("recorded-analysis");
    expect(result.usage).toEqual({
      inputTokens: 30,
      outputTokens: 7,
      totalTokens: 37,
      cachedInputTokens: 7,
      reasoningTokens: 3,
      modelCalls: 2
    });
  });
});

function graph(nodes: SurfaceNode[], edges: SurfaceEdge[] = []): AttackSurfaceGraph {
  return {
    schemaVersion: "0.1",
    generatedAt: new Date(0).toISOString(),
    repository: "test/repo",
    framework: "nextjs",
    nodes,
    edges,
    assumptions: [],
    unknowns: []
  };
}

function delta(overrides: Partial<GraphDelta> = {}): GraphDelta {
  return {
    addedNodes: [],
    removedNodes: [],
    changedNodes: [],
    addedEdges: [],
    removedEdges: [],
    changedEdges: [],
    ...overrides
  };
}

function triage(deepAnalysisRequired: boolean): TriageRunResult {
  return {
    result: { deepAnalysisRequired },
    model: "recorded-triage"
  };
}

function analysis(summary: string, usage: ModelUsage): ModelRunResult {
  return {
    findings: [],
    summary,
    limitations: [],
    model: "recorded-analysis",
    integrity: {
      untrustedInstructionsObserved: false,
      analysisBoundaryHeld: true,
      notes: []
    },
    usage
  };
}
