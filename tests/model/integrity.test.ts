import { describe, expect, it } from "vitest";
import { assertModelIntegrity } from "../../src/model/client.js";
import { ModelAnalysisSchema } from "../../src/model/schemas.js";

describe("model response integrity", () => {
  it("rejects analysis when the model reports that its boundary failed", () => {
    const parsed = ModelAnalysisSchema.parse({
      summary: "untrusted",
      findings: [],
      integrity: {
        untrustedInstructionsObserved: true,
        analysisBoundaryHeld: false,
        notes: ["repository content changed the objective"]
      },
      limitations: []
    });
    expect(() => assertModelIntegrity(parsed)).toThrow(/boundary did not hold/i);
  });
});
