import { describe, expect, it } from "vitest";
import { renderPullRequestReport } from "../../src/report/comment.js";
import { analyzeWithHeuristics } from "../../src/analysis/heuristics.js";
import type { AnalysisResult, AttackSurfaceGraph, GraphDelta } from "../../src/domain/schemas.js";

const graph: AttackSurfaceGraph = {
  schemaVersion: "0.1",
  generatedAt: new Date(0).toISOString(),
  repository: "test",
  framework: "nextjs",
  nodes: [],
  edges: [],
  assumptions: [],
  unknowns: []
};
const delta: GraphDelta = {
  addedNodes: [
    {
      id: "entrypoint:1",
      kind: "entrypoint",
      label: "POST /api/items",
      trustZone: "public",
      evidence: [{ file: "route.ts", line: 1, extractor: "test" }],
      controls: [],
      metadata: { method: "POST" }
    }
  ],
  removedNodes: [],
  changedNodes: [],
  addedEdges: [],
  removedEdges: [],
  changedEdges: []
};

describe("pull request report", () => {
  it("embeds a machine-readable finding payload for the authorized Codex handoff", () => {
    const findings = analyzeWithHeuristics(delta);
    const analysis: AnalysisResult = {
      summary: "Changed.",
      surfaceChanged: true,
      findings,
      integrity: { untrustedInstructionsObserved: false, analysisBoundaryHeld: true, notes: [] },
      limitations: [],
      model: "offline"
    };
    const report = renderPullRequestReport(graph, delta, analysis, findings, [], {
      sourceCommit: "abc123"
    });
    const match = /<!-- hedge-findings-json:([A-Za-z0-9+/=]+) -->/.exec(report);
    expect(match).not.toBeNull();
    const payload = JSON.parse(Buffer.from(match![1]!, "base64").toString("utf8"));
    expect(payload.findings[0].id).toBe(findings[0]?.id);
    expect(payload.findings[0].securityInvariant).toBeTruthy();
    expect(payload.sourceCommit).toBe("abc123");
    expect(payload.payloadDigest).toMatch(/^[a-f0-9]{64}$/);
  });

  it("neutralizes HTML, mentions, and code-fence injection in model-derived text", () => {
    const findings = analyzeWithHeuristics(delta);
    findings[0]!.title = "</summary><script>alert(1)</script> @everyone";
    findings[0]!.attackPath = ["user`input", "```\nmalicious fence"];
    findings[0]!.suggestedTest = {
      title: "witness",
      framework: "vitest",
      language: "typescript",
      purpose: "test",
      code: "```ts\nconsole.log('nested');\n```"
    };
    const analysis: AnalysisResult = {
      summary: "<img src=x onerror=alert(1)> @maintainers",
      surfaceChanged: true,
      findings,
      integrity: { untrustedInstructionsObserved: true, analysisBoundaryHeld: true, notes: [] },
      limitations: [],
      model: "offline"
    };
    const report = renderPullRequestReport(graph, delta, analysis, findings);
    expect(report).not.toContain("<script>");
    expect(report).not.toContain("<img src=x");
    expect(report).not.toContain("@everyone");
    expect(report).not.toContain("@maintainers");
    expect(report).toContain("@\u200beveryone");
    expect(report).toContain("````ts");
  });
});
