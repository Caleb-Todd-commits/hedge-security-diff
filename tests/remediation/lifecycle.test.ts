import { describe, expect, it } from "vitest";
import { applyVerification } from "../../src/verification/lifecycle.js";
import { analyzeWithHeuristics } from "../../src/analysis/heuristics.js";
import type { GraphDelta } from "../../src/domain/schemas.js";

const delta: GraphDelta = {
  addedNodes: [
    {
      id: "entrypoint:admin",
      kind: "entrypoint",
      label: "POST /api/admin",
      trustZone: "public",
      evidence: [{ file: "route.ts", line: 1, extractor: "test" }],
      controls: [],
      metadata: { method: "POST" }
    }
  ],
  removedNodes: [],
  changedNodes: [],
  addedEdges: [],
  removedEdges: [],
  changedEdges: []
};

describe("verification lifecycle", () => {
  it("does not verify merely because a test or mitigation appeared", () => {
    const finding = analyzeWithHeuristics(delta)[0]!;
    const updated = applyVerification(finding, {
      vulnerableRevisionWitnessSucceeded: false,
      repairedRevisionWitnessBlocked: true,
      legitimateBehaviorPassed: true,
      architectureControlChanged: true,
      commands: ["npm test"],
      notes: []
    });
    expect(updated.status).toBe("verification-available");
  });

  it("requires counterfactual and legitimate-behavior evidence", () => {
    const finding = analyzeWithHeuristics(delta)[0]!;
    const updated = applyVerification(finding, {
      vulnerableRevisionWitnessSucceeded: true,
      repairedRevisionWitnessBlocked: true,
      legitimateBehaviorPassed: true,
      architectureControlChanged: true,
      commands: ["npm test"],
      notes: []
    });
    expect(updated.status).toBe("verified");
  });
});
