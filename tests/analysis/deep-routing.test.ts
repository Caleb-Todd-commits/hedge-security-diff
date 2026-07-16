import { describe, expect, it } from "vitest";
import { requiresDeepAnalysisDeterministically } from "../../src/analysis/run.js";
import type { GraphDelta, RiskFinding, SurfaceNode } from "../../src/domain/schemas.js";

const empty: GraphDelta = {
  addedNodes: [],
  removedNodes: [],
  changedNodes: [],
  addedEdges: [],
  removedEdges: [],
  changedEdges: []
};

const component: SurfaceNode = {
  id: "component:service",
  kind: "component",
  label: "Service",
  trustZone: "application",
  evidence: [],
  controls: [],
  metadata: {}
};

function finding(severity: RiskFinding["severity"]): RiskFinding {
  const timestamp = new Date(0).toISOString();
  return {
    id: "HEDGE-PENDING",
    fingerprint: `finding-${severity}`,
    title: `${severity} deterministic recommendation`,
    severity,
    origin: "deterministic",
    status: "open",
    stride: [],
    cwe: [],
    asset: "Application",
    attackerCapability: "Reach the changed surface",
    entryPoint: "Service",
    trustBoundary: "Application",
    precondition: "The change is deployed.",
    attackPath: ["Service"],
    potentialImpact: "The architecture may need a control.",
    existingControls: [],
    missingControls: ["Recommended control"],
    securityInvariant: "The changed surface must retain its intended control.",
    evidence: [],
    confidence: 0.8,
    verificationHistory: [],
    createdAt: timestamp,
    updatedAt: timestamp
  };
}

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

  it("does not force deep analysis for a medium deterministic recommendation", () => {
    expect(requiresDeepAnalysisDeterministically(empty, [finding("medium")])).toBe(false);
  });

  it("forces deep analysis for a high deterministic recommendation", () => {
    expect(requiresDeepAnalysisDeterministically(empty, [finding("high")])).toBe(true);
  });

  it("does not force deep analysis for a generic component call", () => {
    expect(
      requiresDeepAnalysisDeterministically({
        ...empty,
        addedNodes: [component],
        addedEdges: [
          {
            id: "edge:component:dependency",
            from: component.id,
            to: "dependency:utility",
            kind: "calls",
            evidence: [],
            controls: [],
            confidence: 1
          }
        ]
      })
    ).toBe(false);
  });

  it("forces deep analysis when a confirmed control is removed", () => {
    expect(
      requiresDeepAnalysisDeterministically({
        ...empty,
        changedNodes: [
          {
            before: {
              ...component,
              controls: [
                {
                  type: "validation",
                  label: "Validated input",
                  evidence: [],
                  confidence: 1,
                  assurance: "confirmed"
                }
              ]
            },
            after: component
          }
        ]
      })
    ).toBe(true);
  });
});
