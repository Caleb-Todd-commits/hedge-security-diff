import { describe, expect, it } from "vitest";
import { renderSarif } from "../../src/report/sarif.js";
import type { RiskFinding } from "../../src/domain/schemas.js";

const finding: RiskFinding = {
  id: "HEDGE-003",
  fingerprint: "abc123",
  title: "New upload path lacks limits",
  severity: "high",
  origin: "deterministic",
  status: "open",
  stride: ["Tampering"],
  cwe: ["CWE-434"],
  asset: "Storage",
  attackerCapability: "Upload a file",
  entryPoint: "POST /api/files",
  trustBoundary: "public to data",
  precondition: "Route is deployed",
  attackPath: ["User", "POST /api/files", "Storage"],
  potentialImpact: "Unbounded content reaches storage.",
  existingControls: ["Authentication"],
  missingControls: ["Size limit"],
  securityInvariant: "Uploads must be bounded.",
  evidence: [{ file: "app/api/files/route.ts", line: 12, extractor: "test" }],
  confidence: 0.9,
  verificationHistory: [],
  createdAt: new Date(0).toISOString(),
  updatedAt: new Date(0).toISOString()
};

describe("SARIF rendering", () => {
  it("emits a GitHub-compatible SARIF location and stable fingerprint", () => {
    const sarif = renderSarif([finding]);
    const result = sarif.runs[0]!.results[0]!;
    expect(sarif.version).toBe("2.1.0");
    expect(result.ruleId).toBe("HEDGE-003");
    expect(result.level).toBe("error");
    expect(result.locations[0]?.physicalLocation.artifactLocation.uri).toBe(
      "app/api/files/route.ts"
    );
    expect(result.partialFingerprints["hedgeFinding/v1"]).toBe("abc123");
  });
});
