import { describe, expect, it } from "vitest";
import { runAnalysis } from "../../src/analysis/run.js";
import {
  HedgeConfigSchema,
  type AttackSurfaceGraph,
  type GraphDelta
} from "../../src/domain/schemas.js";

const node = {
  id: "entrypoint:admin",
  kind: "entrypoint" as const,
  label: "POST /api/admin/users",
  trustZone: "public" as const,
  evidence: [{ file: "app/api/admin/users/route.ts", line: 1, extractor: "test" }],
  controls: [],
  metadata: { method: "POST" }
};
const graph: AttackSurfaceGraph = {
  schemaVersion: "0.1",
  generatedAt: new Date(0).toISOString(),
  repository: "test/repo",
  framework: "nextjs",
  nodes: [node],
  edges: [],
  assumptions: [],
  unknowns: []
};
const delta: GraphDelta = {
  addedNodes: [node],
  removedNodes: [],
  changedNodes: [],
  addedEdges: [],
  removedEdges: [],
  changedEdges: []
};

describe("observation, inference, and decision separation", () => {
  it("keeps deterministic facts separate from hypotheses and threshold decisions", async () => {
    const result = await runAnalysis({
      graph,
      delta,
      patch: "",
      config: HedgeConfigSchema.parse({ fail_on: "high" })
    });
    expect(result.observations?.some((item) => item.kind === "node-added")).toBe(true);
    expect(result.inferences?.length).toBe(result.findings.length);
    expect(result.inferences?.every((item) => item.observationIds.length > 0)).toBe(true);
    expect(result.decisions?.find((item) => item.source === "threshold")?.type).toBe("block");
    expect(result.observations?.every((item) => item.source === "deterministic")).toBe(true);
  });
});
