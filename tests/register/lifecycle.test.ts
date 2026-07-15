import { describe, expect, it } from "vitest";
import {
  acceptRisk,
  emptyRegister,
  markMissingFindingsAsMitigated,
  mergeFindings,
  recordVerification
} from "../../src/register/store.js";
import { analyzeWithHeuristics } from "../../src/analysis/heuristics.js";
import type { GraphDelta } from "../../src/domain/schemas.js";

const added: GraphDelta = {
  addedNodes: [
    {
      id: "entrypoint:1",
      kind: "entrypoint",
      label: "POST /api/items",
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

describe("risk register lifecycle", () => {
  it("records deliberate acceptance with an audit trail", () => {
    const register = emptyRegister();
    const finding = mergeFindings(register, analyzeWithHeuristics(added)).runFindings[0]!;
    acceptRisk(register, finding.id, "Compensating network control", "caleb");
    expect(finding.status).toBe("accepted");
    expect(register.acceptedRisks[0]).toMatchObject({ riskId: finding.id, acceptedBy: "caleb" });
  });

  it("marks a missing finding as mitigation detected, never verified", () => {
    const register = emptyRegister();
    const finding = mergeFindings(register, analyzeWithHeuristics(added)).runFindings[0]!;
    const changed: GraphDelta = {
      ...added,
      addedNodes: [],
      changedNodes: [
        {
          before: added.addedNodes[0]!,
          after: {
            ...added.addedNodes[0]!,
            controls: [{ type: "authentication", label: "auth", evidence: [], confidence: 1 }]
          }
        }
      ]
    };
    const updates = markMissingFindingsAsMitigated(register, [], changed);
    expect(updates[0]?.status).toBe("mitigation-detected");
  });

  it("persists verification evidence and verifies only the complete counterfactual", () => {
    const register = emptyRegister();
    const finding = mergeFindings(register, analyzeWithHeuristics(added)).runFindings[0]!;
    const updated = recordVerification(register, finding.id, {
      vulnerableRevisionWitnessSucceeded: true,
      repairedRevisionWitnessBlocked: true,
      legitimateBehaviorPassed: true,
      architectureControlChanged: true,
      commands: ["npm test"]
    });
    expect(updated.status).toBe("verified");
    expect(updated.verificationHistory).toHaveLength(1);
  });
  it("reopens a previously verified risk when the same active fingerprint returns", () => {
    const register = emptyRegister();
    const proposals = analyzeWithHeuristics(added);
    const finding = mergeFindings(register, proposals).runFindings[0]!;
    const verified = recordVerification(register, finding.id, {
      vulnerableRevisionWitnessSucceeded: true,
      repairedRevisionWitnessBlocked: true,
      legitimateBehaviorPassed: true,
      architectureControlChanged: true
    });
    expect(verified.status).toBe("verified");

    const repeated = mergeFindings(register, proposals).runFindings[0]!;
    expect(repeated.status).toBe("open");
  });
});

describe("model finding lifecycle safety", () => {
  it("does not mark model-only findings mitigated when deep model analysis did not complete", () => {
    const register = emptyRegister();
    const proposal = { ...analyzeWithHeuristics(added)[0]!, origin: "model" as const };
    mergeFindings(register, [proposal]);
    const changed: GraphDelta = {
      ...added,
      addedNodes: [],
      changedNodes: [
        {
          before: added.addedNodes[0]!,
          after: {
            ...added.addedNodes[0]!,
            controls: [{ type: "authentication", label: "auth", evidence: [], confidence: 1 }]
          }
        }
      ]
    };
    const updates = markMissingFindingsAsMitigated(register, [], changed, {
      modelAnalysisCompleted: false
    });
    expect(updates).toHaveLength(0);
    expect(register.findings[0]?.status).toBe("open");
  });

  it("can mark a model-only finding mitigated after a complete deep analysis", () => {
    const register = emptyRegister();
    const proposal = { ...analyzeWithHeuristics(added)[0]!, origin: "model" as const };
    mergeFindings(register, [proposal]);
    const changed: GraphDelta = {
      ...added,
      addedNodes: [],
      changedNodes: [
        {
          before: added.addedNodes[0]!,
          after: {
            ...added.addedNodes[0]!,
            controls: [{ type: "authentication", label: "auth", evidence: [], confidence: 1 }]
          }
        }
      ]
    };
    const updates = markMissingFindingsAsMitigated(register, [], changed, {
      modelAnalysisCompleted: true
    });
    expect(updates).toHaveLength(1);
    expect(register.findings[0]?.status).toBe("mitigation-detected");
  });
});
