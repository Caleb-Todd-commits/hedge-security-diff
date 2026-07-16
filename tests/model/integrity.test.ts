import { describe, expect, it } from "vitest";
import { assertModelIntegrity } from "../../src/model/client.js";
import { ModelAnalysisSchema } from "../../src/model/schemas.js";

describe("model response integrity", () => {
  it("rejects analysis when the model reports that its boundary failed", () => {
    const parsed = ModelAnalysisSchema.parse({
      findings: [],
      integrity: {
        untrustedInstructionsObserved: true,
        analysisBoundaryHeld: false
      }
    });
    expect(() => assertModelIntegrity(parsed)).toThrow(/boundary did not hold/i);
  });
});
