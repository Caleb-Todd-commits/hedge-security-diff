import { describe, expect, it } from "vitest";
import { buildDecisions } from "../../src/analysis/decisions.js";
import type { RiskFinding } from "../../src/domain/schemas.js";

function finding(origin: RiskFinding["origin"]): RiskFinding {
  const now = new Date(0).toISOString();
  return {
    id: "HEDGE-001",
    fingerprint: `risk-${origin}`,
    title: "Evidence-linked risk",
    severity: "critical",
    origin,
    status: "open",
    stride: [],
    cwe: [],
    asset: "data",
    attackerCapability: "reach route",
    entryPoint: "POST /api/example",
    trustBoundary: "public to app",
    precondition: "route is reachable",
    attackPath: ["route"],
    potentialImpact: "unexpected access",
    existingControls: [],
    missingControls: ["authorization"],
    securityInvariant: "authorization is required",
    evidence: [{ file: "app/api/example/route.ts", line: 1, extractor: "test" }],
    confidence: 0.9,
    verificationHistory: [],
    createdAt: now,
    updatedAt: now
  };
}

describe("recorded decisions", () => {
  it("does not let a model-origin finding directly block", () => {
    const decisions = buildDecisions([finding("model")], [], [], [], "high", {
      status: "complete",
      reasons: []
    });
    expect(decisions[0]).toMatchObject({ source: "threshold", type: "warn" });
  });

  it("keeps deterministic findings eligible for the configured threshold", () => {
    const decisions = buildDecisions([finding("deterministic")], [], [], [], "high", {
      status: "complete",
      reasons: []
    });
    expect(decisions[0]).toMatchObject({ source: "threshold", type: "block" });
  });

  it("does not block on a finding whose trusted lifecycle state is accepted", () => {
    const accepted = { ...finding("deterministic"), status: "accepted" as const };
    const decisions = buildDecisions([accepted], [], [], [], "high", {
      status: "complete",
      reasons: []
    });
    expect(decisions[0]).toMatchObject({ source: "threshold", type: "allow" });
  });

  it("records degraded coverage as a separate warning decision", () => {
    const decisions = buildDecisions([], [], [], [], "high", {
      status: "degraded",
      reasons: ["Coverage was partial."]
    });
    expect(decisions).toContainEqual(
      expect.objectContaining({ source: "analysis-health", type: "warn" })
    );
  });
});
