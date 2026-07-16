import { describe, expect, it } from "vitest";
import { analyzeWithHeuristics } from "../../src/analysis/heuristics.js";
import type { GraphDelta, SurfaceNode } from "../../src/domain/schemas.js";
import { deriveArchitectureControlProof } from "../../src/verification/architecture.js";

const baseCommit = "a".repeat(40);
const headCommit = "b".repeat(40);

const vulnerableNode: SurfaceNode = {
  id: "entrypoint:post-api-items",
  kind: "entrypoint",
  label: "POST /api/items",
  trustZone: "public",
  evidence: [{ file: "app/api/items/route.ts", line: 4, extractor: "test" }],
  controls: [],
  metadata: { method: "POST" }
};

function emptyDelta(): GraphDelta {
  return {
    addedNodes: [],
    removedNodes: [],
    changedNodes: [],
    addedEdges: [],
    removedEdges: [],
    changedEdges: []
  };
}

function finding() {
  return analyzeWithHeuristics({ ...emptyDelta(), addedNodes: [vulnerableNode] })[0]!;
}

describe("architecture verification proof", () => {
  it("proves a relevant control change with exact base/head provenance", () => {
    const repairedNode: SurfaceNode = {
      ...vulnerableNode,
      controls: [
        {
          type: "authorization",
          label: "requireOwner",
          confidence: 1,
          assurance: "confirmed",
          evidence: [{ file: "app/api/items/route.ts", line: 5, extractor: "test" }]
        }
      ]
    };
    const proof = deriveArchitectureControlProof(
      { ...emptyDelta(), changedNodes: [{ before: vulnerableNode, after: repairedNode }] },
      finding(),
      { baseCommit, headCommit }
    );

    expect(proof.changed).toBe(true);
    expect(proof.graphDeltaDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(proof.subjectIds).toEqual([vulnerableNode.id]);
    expect(proof.architectureEvidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          commit: baseCommit,
          snapshot: "base",
          subjectId: vulnerableNode.id
        }),
        expect.objectContaining({
          commit: headCommit,
          snapshot: "head",
          subjectId: vulnerableNode.id
        })
      ])
    );
  });

  it("does not accept an unrelated architecture change", () => {
    const unrelated = {
      ...vulnerableNode,
      id: "entrypoint:get-health",
      label: "GET /api/health",
      evidence: [{ file: "app/api/health/route.ts", line: 1, extractor: "test" }],
      trustZone: "application" as const
    };
    const proof = deriveArchitectureControlProof(
      {
        ...emptyDelta(),
        changedNodes: [
          {
            before: { ...unrelated, trustZone: "public" },
            after: unrelated
          }
        ]
      },
      finding(),
      { baseCommit, headCommit }
    );
    expect(proof.changed).toBe(false);
    expect(proof.architectureEvidence).toEqual([]);
  });

  it("does not treat an isolated test file as an architecture control", () => {
    const testNode: SurfaceNode = {
      id: "component:test",
      kind: "component",
      label: "regression witness",
      trustZone: "application",
      evidence: [{ file: "hedge-tests/risk.test.ts", line: 1, extractor: "test" }],
      controls: [],
      metadata: {}
    };
    const proof = deriveArchitectureControlProof(
      { ...emptyDelta(), addedNodes: [testNode] },
      finding(),
      { baseCommit, headCommit }
    );
    expect(proof.changed).toBe(false);
  });
});
