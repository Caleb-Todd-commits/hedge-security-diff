import { describe, expect, it } from "vitest";
import { renderHtmlReport } from "../../src/report/html.js";
import type { AnalysisResult, AttackSurfaceGraph, GraphDelta } from "../../src/domain/schemas.js";

const baseline: AttackSurfaceGraph = {
  schemaVersion: "0.1",
  generatedAt: new Date(0).toISOString(),
  repository: "demo/repo",
  framework: "nextjs",
  nodes: [],
  edges: [],
  assumptions: [],
  unknowns: []
};
const graph: AttackSurfaceGraph = {
  ...baseline,
  nodes: [
    {
      id: "entry:1",
      kind: "entrypoint",
      label: "POST /api/files",
      trustZone: "public",
      evidence: [{ file: "app/api/files/route.ts", line: 1, extractor: "test" }],
      controls: [],
      metadata: {}
    }
  ]
};
const delta: GraphDelta = {
  addedNodes: graph.nodes,
  removedNodes: [],
  changedNodes: [],
  addedEdges: [],
  removedEdges: [],
  changedEdges: []
};
const analysis: AnalysisResult = {
  summary: "A new upload surface was added.",
  surfaceChanged: true,
  findings: [],
  integrity: { untrustedInstructionsObserved: false, analysisBoundaryHeld: true, notes: [] },
  limitations: [],
  model: "deterministic"
};

describe("HTML report", () => {
  it("produces a standalone escaped dashboard", () => {
    const html = renderHtmlReport(baseline, graph, delta, analysis, [], {
      repository: "demo/<repo>"
    });
    expect(html).toContain("Hedge · security architecture diff");
    expect(html).toContain("demo/&lt;repo&gt;");
    expect(html).toContain("application/json");
    expect(html).not.toContain("demo/<repo>");
  });
});
