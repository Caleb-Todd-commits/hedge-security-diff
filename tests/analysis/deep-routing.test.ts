import { describe, expect, it } from "vitest";
import { requiresDeepAnalysisDeterministically } from "../../src/analysis/run.js";
import type { GraphDelta } from "../../src/domain/schemas.js";

const empty: GraphDelta = {
  addedNodes: [],
  removedNodes: [],
  changedNodes: [],
  addedEdges: [],
  removedEdges: [],
  changedEdges: []
};

describe("deterministic deep-analysis routing", () => {
  it("forces deep analysis for changed entry points", () => {
    expect(
      requiresDeepAnalysisDeterministically({
        ...empty,
        addedNodes: [
          {
            id: "entrypoint:1",
            kind: "entrypoint",
            label: "GET /api/items",
            trustZone: "public",
            evidence: [],
            controls: [],
            metadata: { method: "GET" }
          }
        ]
      })
    ).toBe(true);
  });

  it("allows low-cost triage to decide dependency-only changes", () => {
    expect(
      requiresDeepAnalysisDeterministically({
        ...empty,
        addedNodes: [
          {
            id: "dependency:test",
            kind: "dependency",
            label: "test@1.0.0",
            trustZone: "external",
            evidence: [],
            controls: [],
            metadata: {}
          }
        ]
      })
    ).toBe(false);
  });
});
