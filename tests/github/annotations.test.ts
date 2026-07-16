import { describe, expect, it } from "vitest";
import { createFindingAnnotations } from "../../src/github/annotations.js";
import type { RiskFinding } from "../../src/domain/schemas.js";

function finding(severity: RiskFinding["severity"]): RiskFinding {
  return {
    id: "HEDGE-001",
    fingerprint: "f",
    title: "Risk",
    severity,
    origin: "deterministic",
    status: "open",
    stride: [],
    cwe: [],
    asset: "asset",
    attackerCapability: "capability",
    entryPoint: "POST /api/test",
    trustBoundary: "public to app",
    precondition: "deployed",
    attackPath: ["User", "Route"],
    potentialImpact: "impact",
    existingControls: [],
    missingControls: ["auth"],
    securityInvariant: "must authenticate",
    evidence: [{ file: "route.ts", line: 7, extractor: "test" }],
    confidence: 0.9,
    verificationHistory: [],
    createdAt: new Date(0).toISOString(),
    updatedAt: new Date(0).toISOString()
  };
}

describe("GitHub annotations", () => {
  it("maps high findings to file-scoped errors", () => {
    expect(createFindingAnnotations([finding("high")])).toEqual([
      expect.objectContaining({ level: "error", file: "route.ts", startLine: 7 })
    ]);
  });

  it("caps output to avoid annotation spam", () => {
    expect(
      createFindingAnnotations(
        Array.from({ length: 30 }, () => finding("low")),
        5
      )
    ).toHaveLength(5);
  });

  it("bounds untrusted annotation text and neutralizes mentions", () => {
    const large = finding("high");
    large.title = `@maintainers ${"x".repeat(1_000)}`;
    large.potentialImpact = "y".repeat(10_000);
    const [annotation] = createFindingAnnotations([large]);
    expect(annotation?.title.length).toBeLessThanOrEqual(240);
    expect(annotation?.message.length).toBeLessThanOrEqual(4_000);
    expect(annotation?.title).not.toContain("@maintainers");
  });
});
