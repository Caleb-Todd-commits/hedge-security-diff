import { describe, expect, it } from "vitest";
import { analyzeSecurityInvariants } from "../../src/analysis/invariants.js";
import { HedgeConfigSchema, type GraphDelta } from "../../src/domain/schemas.js";

function deltaWithControls(controls: Array<"authentication" | "size-limit">): GraphDelta {
  return {
    addedNodes: [
      {
        id: "entrypoint:upload",
        kind: "entrypoint",
        label: "POST /api/files/upload",
        trustZone: "public",
        evidence: [{ file: "app/api/files/upload/route.ts", line: 1, extractor: "test" }],
        controls: controls.map((type) => ({
          type,
          label: type,
          evidence: [],
          confidence: 1,
          assurance: "confirmed" as const
        })),
        metadata: { method: "POST" }
      }
    ],
    removedNodes: [],
    changedNodes: [],
    addedEdges: [],
    removedEdges: [],
    changedEdges: []
  };
}

const invariant = HedgeConfigSchema.parse({
  invariants: [
    {
      id: "INV-UPLOAD",
      description: "Public upload routes require authentication and a size limit.",
      severity: "high",
      applies_to: {
        kinds: ["entrypoint"],
        trust_zones: ["public"],
        methods: ["POST"],
        label_pattern: "* /api/files/*"
      },
      requires: { controls: ["authentication", "size-limit"] },
      rationale: "Unbounded anonymous uploads can consume storage and introduce hostile content."
    }
  ]
}).invariants[0]!;

describe("security invariants", () => {
  it("creates an explicit violation and evidence-linked finding", () => {
    const result = analyzeSecurityInvariants(deltaWithControls([]), [invariant]);
    expect(result.evaluations).toMatchObject([
      {
        invariantId: "INV-UPLOAD",
        status: "violated",
        missingControls: ["authentication", "size-limit"]
      }
    ]);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ origin: "invariant", confidence: 1 });
  });

  it("records satisfaction without inventing a finding", () => {
    const result = analyzeSecurityInvariants(deltaWithControls(["authentication", "size-limit"]), [
      invariant
    ]);
    expect(result.evaluations[0]?.status).toBe("satisfied");
    expect(result.findings).toEqual([]);
  });

  it("treats inferred controls as unknown rather than satisfied", () => {
    const delta = deltaWithControls(["authentication", "size-limit"]);
    for (const control of delta.addedNodes[0]!.controls) control.assurance = "inferred";
    const result = analyzeSecurityInvariants(delta, [invariant]);
    expect(result.evaluations[0]?.status).toBe("unknown");
    expect(result.findings).toEqual([]);
  });

  it("does not evaluate an invariant as healthy under partial coverage", () => {
    const result = analyzeSecurityInvariants(
      deltaWithControls(["authentication", "size-limit"]),
      [invariant],
      {
        coverage: {
          status: "partial",
          discoveredFiles: 2,
          includedFiles: 1,
          includedBytes: 100,
          omitted: { fileLimit: 1, byteLimit: 0, unsafeOrUnreadable: 0, binary: 0 },
          diagnostics: []
        }
      }
    );
    expect(result.evaluations[0]?.status).toBe("unknown");
    expect(result.findings).toEqual([]);
  });
});
