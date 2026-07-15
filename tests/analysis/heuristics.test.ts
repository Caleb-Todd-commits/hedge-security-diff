import { describe, expect, it } from "vitest";
import { analyzeWithHeuristics } from "../../src/analysis/heuristics.js";
import type { GraphDelta, SurfaceNode } from "../../src/domain/schemas.js";

const uploadRoute: SurfaceNode = {
  id: "entrypoint:upload",
  kind: "entrypoint",
  label: "POST /api/files/upload",
  trustZone: "public",
  evidence: [{ file: "app/api/files/upload/route.ts", line: 2, extractor: "test" }],
  controls: [],
  metadata: { method: "POST" }
};
const storage: SurfaceNode = {
  id: "storage:write",
  kind: "storage",
  label: "Storage write",
  trustZone: "data",
  evidence: [{ file: "app/api/files/upload/route.ts", line: 5, extractor: "test" }],
  controls: [],
  metadata: {}
};

const delta: GraphDelta = {
  addedNodes: [uploadRoute, storage],
  removedNodes: [],
  changedNodes: [],
  addedEdges: [
    {
      id: "edge:upload-storage",
      from: uploadRoute.id,
      to: storage.id,
      kind: "writes",
      evidence: storage.evidence,
      controls: [],
      confidence: 0.9
    }
  ],
  removedEdges: [],
  changedEdges: []
};

describe("deterministic risk heuristics", () => {
  it("surfaces authentication and upload boundary risks", () => {
    const findings = analyzeWithHeuristics(delta);
    expect(findings.length).toBeGreaterThanOrEqual(2);
    expect(findings.some((finding) => finding.title.includes("authentication"))).toBe(true);
    expect(findings.some((finding) => finding.title.includes("storage write"))).toBe(true);
  });
});
