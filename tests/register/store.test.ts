import { describe, expect, it } from "vitest";
import { emptyRegister, mergeFindings } from "../../src/register/store.js";
import { analyzeWithHeuristics } from "../../src/analysis/heuristics.js";
import type { GraphDelta } from "../../src/domain/schemas.js";

const delta: GraphDelta = {
  addedNodes: [
    {
      id: "entrypoint:admin",
      kind: "entrypoint",
      label: "DELETE /api/admin/users",
      trustZone: "public",
      evidence: [{ file: "route.ts", line: 1, extractor: "test" }],
      controls: [],
      metadata: { method: "DELETE" }
    }
  ],
  removedNodes: [],
  changedNodes: [],
  addedEdges: [],
  removedEdges: [],
  changedEdges: []
};

describe("threat register", () => {
  it("assigns stable IDs and deduplicates every fingerprint", () => {
    const register = emptyRegister();
    const proposals = analyzeWithHeuristics(delta);
    const first = mergeFindings(register, proposals);
    const firstIds = first.runFindings.map((finding) => finding.id);
    const second = mergeFindings(first.register, proposals);

    expect(proposals.length).toBeGreaterThanOrEqual(1);
    expect(firstIds[0]).toBe("HEDGE-001");
    expect(second.register.findings).toHaveLength(proposals.length);
    expect(second.runFindings.map((finding) => finding.id)).toEqual(firstIds);
  });
});
