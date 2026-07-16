import { describe, expect, it } from "vitest";
import { applyVerification, assessVerificationEvidence } from "../../src/verification/lifecycle.js";
import { analyzeWithHeuristics } from "../../src/analysis/heuristics.js";
import { VerificationEvidenceSchema, type GraphDelta } from "../../src/domain/schemas.js";

const vulnerableRevision = "a".repeat(40);
const repairedRevision = "b".repeat(40);
const digest = "c".repeat(64);

function completeEvidence() {
  return {
    vulnerableRevision,
    repairedRevision,
    vulnerableRevisionWitnessSucceeded: true,
    repairedRevisionWitnessBlocked: true,
    legitimateBehaviorPassed: true,
    architectureControlChanged: true,
    witnessDigest: digest,
    vulnerableOutcome: "reproduced" as const,
    repairedOutcome: "blocked-by-control" as const,
    graphDeltaDigest: "d".repeat(64),
    architectureEvidence: [
      {
        file: "route.ts",
        line: 1,
        extractor: "test",
        commit: repairedRevision,
        snapshot: "head" as const,
        subjectId: "entrypoint:admin"
      }
    ],
    commands: ["immutable witness bundle"],
    notes: []
  };
}

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

  it("keeps legacy boolean-only evidence readable but ineligible for verification", () => {
    const finding = analyzeWithHeuristics(delta)[0]!;
    const updated = applyVerification(finding, {
      vulnerableRevisionWitnessSucceeded: true,
      repairedRevisionWitnessBlocked: true,
      legitimateBehaviorPassed: true,
      architectureControlChanged: true,
      commands: ["npm test"],
      notes: []
    });
    expect(updated.status).toBe("verification-available");
  });

  it("requires one immutable witness, structured outcomes, and exact architecture evidence", () => {
    const finding = analyzeWithHeuristics(delta)[0]!;
    const updated = applyVerification(finding, completeEvidence());
    expect(updated.status).toBe("verified");
  });

  it.each([
    ["ordinary witness failure", { repairedOutcome: "inconclusive" as const }],
    ["legitimate behavior failure", { legitimateBehaviorPassed: false }],
    ["missing architecture proof", { architectureEvidence: [] }],
    [
      "evidence from a different commit",
      {
        architectureEvidence: [
          {
            file: "route.ts",
            extractor: "test",
            commit: "e".repeat(40),
            snapshot: "head" as const,
            subjectId: "entrypoint:admin"
          }
        ]
      }
    ]
  ])("does not verify for %s", (_label, override) => {
    const finding = analyzeWithHeuristics(delta)[0]!;
    const updated = applyVerification(finding, { ...completeEvidence(), ...override });
    expect(updated.status).toBe("verification-available");
  });

  it("explains why an inconclusive run cannot verify", () => {
    const evidence = VerificationEvidenceSchema.parse({
      ...completeEvidence(),
      repairedOutcome: "inconclusive"
    });
    expect(assessVerificationEvidence(evidence)).toMatchObject({
      verified: false,
      reasons: expect.arrayContaining(["repaired witness outcome was not blocked-by-control"])
    });
  });
});
