import { describe, expect, it } from "vitest";
import {
  MAX_PULL_REQUEST_COMMENT_BYTES,
  MAX_VISIBLE_COMMENT_BYTES,
  renderPullRequestReport
} from "../../src/report/comment.js";
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

  it("leads with reviewer decisions and links evidence to exact commits", () => {
    const findings = analyzeWithHeuristics(delta);
    findings[0]!.evidence[0]!.endLine = 3;
    const baseCommit = "a".repeat(40);
    const headCommit = "b".repeat(40);
    const analysis: AnalysisResult = {
      summary: "A public POST route now reaches a protected data operation.",
      surfaceChanged: true,
      confirmedNoDelta: false,
      coverage: {
        status: "partial",
        discoveredFiles: 3,
        includedFiles: 2,
        includedBytes: 900,
        omitted: { fileLimit: 0, byteLimit: 1, unsafeOrUnreadable: 0, binary: 0 },
        diagnostics: [
          { code: "byte-limit", phase: "collection", message: "One file exceeded the budget." }
        ]
      },
      analysisHealth: { status: "degraded", reasons: ["Coverage is partial."] },
      findings,
      decisions: [
        {
          id: "decision:health",
          type: "warn",
          reason: "Coverage is partial.",
          source: "analysis-health",
          riskFingerprints: [],
          invariantIds: [],
          observationIds: [],
          inferenceIds: []
        }
      ],
      integrity: { untrustedInstructionsObserved: false, analysisBoundaryHeld: true, notes: [] },
      limitations: [],
      model: "offline"
    };

    const report = renderPullRequestReport(graph, delta, analysis, findings, [], {
      repository: "example/hedge-app",
      baseCommit,
      headCommit
    });

    expect(report.indexOf("### 1. What changed")).toBeLessThan(
      report.indexOf("### 2. Recorded decision")
    );
    expect(report.indexOf("### 2. Recorded decision")).toBeLessThan(
      report.indexOf("### 3. Exact evidence")
    );
    expect(report.indexOf("### 3. Exact evidence")).toBeLessThan(
      report.indexOf("### 4. Next action")
    );
    expect(report.indexOf("### 4. Next action")).toBeLessThan(
      report.indexOf("### 5. Coverage and health")
    );
    expect(report).toContain(
      `https://github.com/example/hedge-app/blob/${headCommit}/route.ts#L1-L3`
    );
    expect(report).toContain("Coverage: **PARTIAL**");
    expect(report).toContain("Analysis health: **DEGRADED**");
    expect(report).toContain("<summary><strong>Technical details, graph, and limitations</strong>");
  });

  it("keeps visible and total comment content within publication budgets", () => {
    const seed = analyzeWithHeuristics(delta)[0]!;
    const findings = Array.from({ length: 40 }, (_, index) => ({
      ...structuredClone(seed),
      id: `HEDGE-${String(index + 1).padStart(3, "0")}`,
      fingerprint: `fingerprint-${index}`,
      title: `Large but bounded finding ${index} ${"x".repeat(1_000)}`,
      securityInvariant: "The architecture control must remain explicit. ".repeat(100),
      attackPath: Array.from({ length: 30 }, () =>
        "untrusted request crosses a boundary".repeat(20)
      ),
      evidence: Array.from({ length: 30 }, () => ({
        file: `app/api/${"nested/".repeat(20)}route-${index}.ts`,
        line: 1,
        extractor: "test"
      })),
      suggestedTest: {
        title: "large witness",
        framework: "vitest",
        language: "typescript",
        purpose: "exercise the changed architecture",
        code: "expect(true).toBe(true);\n".repeat(2_000)
      }
    }));
    const analysis: AnalysisResult = {
      summary: "Changed architecture. ".repeat(1_000),
      surfaceChanged: true,
      findings,
      integrity: { untrustedInstructionsObserved: false, analysisBoundaryHeld: true, notes: [] },
      limitations: [],
      model: "offline"
    };
    const report = renderPullRequestReport(graph, delta, analysis, findings, [], {
      repository: "example/hedge-app",
      headCommit: "c".repeat(40)
    });
    const visible = report.replace(/\n\n<!-- hedge-findings-json:[A-Za-z0-9+/=]+ -->$/, "");
    expect(Buffer.byteLength(visible, "utf8")).toBeLessThanOrEqual(MAX_VISIBLE_COMMENT_BYTES);
    expect(Buffer.byteLength(report, "utf8")).toBeLessThanOrEqual(MAX_PULL_REQUEST_COMMENT_BYTES);
    expect(report).toContain("detail section(s) were omitted");
  });
});
