import { describe, expect, it } from "vitest";
import { analyzeWithCustomPolicies } from "../../src/analysis/policies.js";
import { HedgeConfigSchema, type GraphDelta } from "../../src/domain/schemas.js";

const delta: GraphDelta = {
  addedNodes: [
    {
      id: "entrypoint:billing",
      kind: "entrypoint",
      label: "POST /api/billing/charge",
      trustZone: "public",
      evidence: [{ file: "app/api/billing/charge/route.ts", line: 3, extractor: "test" }],
      controls: [{ type: "authentication", label: "auth()", evidence: [], confidence: 1 }],
      metadata: { method: "POST" }
    }
  ],
  removedNodes: [],
  changedNodes: [],
  addedEdges: [],
  removedEdges: [],
  changedEdges: []
};

describe("organization-defined policies", () => {
  it("surfaces missing controls on matching changed architecture", () => {
    const config = HedgeConfigSchema.parse({
      policies: [
        {
          id: "billing-rate-limit",
          name: "Billing endpoints require rate limiting",
          severity: "high",
          match: {
            kinds: ["entrypoint"],
            trust_zones: ["public"],
            methods: ["POST"],
            label_pattern: "* /api/billing/*"
          },
          require_controls: ["authentication", "rate-limit"],
          security_invariant: "Public billing endpoints must authenticate and enforce rate limits.",
          potential_impact: "Automated abuse may create fraudulent billing operations."
        }
      ]
    });
    const findings = analyzeWithCustomPolicies(delta, config.policies);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.missingControls).toEqual(["rate-limit"]);
    expect(findings[0]!.fingerprint).not.toContain("HEDGE-PENDING");
  });

  it("stays silent when all required controls are present", () => {
    const protectedDelta = structuredClone(delta);
    protectedDelta.addedNodes[0]!.controls.push({
      type: "rate-limit",
      label: "limit()",
      evidence: [],
      confidence: 1
    });
    const config = HedgeConfigSchema.parse({
      policies: [
        {
          id: "billing-rate-limit",
          name: "Billing endpoints require rate limiting",
          match: { label_pattern: "* /api/billing/*" },
          require_controls: ["authentication", "rate-limit"],
          security_invariant: "Public billing endpoints must authenticate and enforce rate limits.",
          potential_impact: "Automated abuse may create fraudulent billing operations."
        }
      ]
    });
    expect(analyzeWithCustomPolicies(protectedDelta, config.policies)).toEqual([]);
  });
});
