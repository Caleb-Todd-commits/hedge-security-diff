import { describe, expect, it } from "vitest";
import { resolve } from "node:path";
import { runEvalSuite } from "../../src/eval/runner.js";

describe("DriftBench deterministic fixtures", () => {
  it("passes the bundled deterministic cases", async () => {
    const summary = await runEvalSuite(resolve("eval/fixtures"));
    expect(summary.total).toBeGreaterThanOrEqual(30);
    expect(summary.failed).toBe(0);
    expect(summary.benignSilenceRate).toBe(1);
    expect(summary.surfaceChangeRecall).toBe(1);
    expect(summary.expectedFindingRecall).toBe(1);
    expect(summary.deterministicStabilityRate).toBe(1);
  });
});
