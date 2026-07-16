import { describe, expect, it } from "vitest";
import type {
  AttackSurfaceGraph,
  Evidence,
  GraphDelta,
  SurfaceEdge,
  SurfaceNode
} from "../../src/domain/schemas.js";
import {
  ANALYSIS_PATCH_MAX_BYTES,
  GRAPH_CONTEXT_ITEM_MAX_BYTES,
  GRAPH_CONTEXT_MAX_ITEMS,
  PATCH_OMISSION_MARKER,
  TRIAGE_PATCH_MAX_BYTES,
  analysisInput,
  buildPromptEvidenceIndex,
  controlEvidenceReference,
  evidenceReference,
  triageInput,
  truncateUtf8,
  type EvidenceChange
} from "../../src/model/prompts.js";

const START = "<HEDGE_UNTRUSTED_REPOSITORY_DATA>\n";
const END = "\n</HEDGE_UNTRUSTED_REPOSITORY_DATA>";

function evidence(name: string, snapshot: "base" | "head"): Evidence {
  return {
    file: `src/${name}.ts`,
    line: 3,
    endLine: 4,
    snippet: `const ${name} = true;`,
    extractor: "prompt-test",
    commit: snapshot === "base" ? "base-sha" : "head-sha",
    snapshot,
    subjectId: name
  };
}

function node(id: string, snapshot: "base" | "head", label = id): SurfaceNode {
  return {
    id,
    kind: "entrypoint",
    label,
    trustZone: "public",
    evidence: [evidence(`${id}-subject`, snapshot)],
    controls: [
      {
        type: "authentication",
        label: "Session authentication",
        evidence: [evidence(`${id}-control`, snapshot)],
        confidence: 0.9,
        assurance: "confirmed"
      }
    ],
    metadata: { method: "POST", path: `/${id}` }
  };
}

function edge(id: string, from: string, to: string, snapshot: "base" | "head"): SurfaceEdge {
  return {
    id,
    from,
    to,
    kind: "calls",
    label: `${from} calls ${to}`,
    evidence: [evidence(`${id}-subject`, snapshot)],
    controls: [
      {
        type: "validation",
        label: "Request validation",
        evidence: [evidence(`${id}-control`, snapshot)],
        confidence: 0.8,
        assurance: "confirmed"
      }
    ],
    confidence: 0.95
  };
}

function fixture(): { graph: AttackSurfaceGraph; delta: GraphDelta } {
  const addedNode = node("node:added", "head");
  const removedNode = node("node:removed", "base");
  const beforeNode = node("node:changed", "base", "Before node");
  const afterNode = node("node:changed", "head", "After node");
  const contextNode = node("node:context", "head", "Context endpoint");
  const addedEdge = edge("edge:added", contextNode.id, addedNode.id, "head");
  const removedEdge = edge("edge:removed", removedNode.id, contextNode.id, "base");
  const beforeEdge = edge("edge:changed", beforeNode.id, contextNode.id, "base");
  const afterEdge = edge("edge:changed", afterNode.id, contextNode.id, "head");
  return {
    graph: {
      schemaVersion: "0.1",
      generatedAt: "2026-07-16T00:00:00.000Z",
      repository: "owner/repo",
      sourceCommit: "head-sha",
      framework: "nextjs",
      nodes: [addedNode, afterNode, contextNode],
      edges: [addedEdge, afterEdge],
      assumptions: [],
      unknowns: []
    },
    delta: {
      addedNodes: [addedNode],
      removedNodes: [removedNode],
      changedNodes: [{ before: beforeNode, after: afterNode }],
      addedEdges: [addedEdge],
      removedEdges: [removedEdge],
      changedEdges: [{ before: beforeEdge, after: afterEdge }]
    }
  };
}

function unwrap(value: string): Record<string, any> {
  expect(value.startsWith(START)).toBe(true);
  expect(value.endsWith(END)).toBe(true);
  return JSON.parse(value.slice(START.length, -END.length)) as Record<string, any>;
}

describe("model prompt inputs", () => {
  it("uses compact JSON and omits duplicated evidence from the structural delta", () => {
    const { graph, delta } = fixture();
    const input = analysisInput(graph, delta, "diff --git a/a.ts b/a.ts");
    const payload = unwrap(input);

    expect(input).not.toContain('\n  "objective"');
    expect(payload.delta.addedNodes[0].evidence).toBeUndefined();
    expect(payload.delta.addedNodes[0].controls[0].evidence).toBeUndefined();
    expect(payload.delta.addedNodes[0].evidenceRefs).toEqual([
      evidenceReference("node", "added", "node:added", 0)
    ]);
    expect(payload.delta.addedNodes[0].controls[0].evidenceRefs).toEqual([
      controlEvidenceReference("node", "added", "node:added", 0, 0)
    ]);
  });

  it("indexes exact subject and control evidence for every delta side", () => {
    const { graph, delta } = fixture();
    const index = buildPromptEvidenceIndex(graph, delta);
    const expectedSubjects: Array<["node" | "edge", EvidenceChange, string]> = [
      ["node", "added", "node:added"],
      ["node", "removed", "node:removed"],
      ["node", "before", "node:changed"],
      ["node", "after", "node:changed"],
      ["edge", "added", "edge:added"],
      ["edge", "removed", "edge:removed"],
      ["edge", "before", "edge:changed"],
      ["edge", "after", "edge:changed"],
      ["node", "context", "node:context"]
    ];

    for (const [subjectType, change, id] of expectedSubjects) {
      const subjectRef = evidenceReference(subjectType, change, id, 0);
      const controlRef = controlEvidenceReference(subjectType, change, id, 0, 0);
      expect(index[subjectRef]?.source).toBe("subject");
      expect(index[controlRef]?.source).toBe("control");
    }

    expect(index[evidenceReference("node", "removed", "node:removed", 0)]?.evidence).toEqual(
      evidence("node:removed-subject", "base")
    );
    expect(
      index[controlEvidenceReference("edge", "after", "edge:changed", 0, 0)]?.evidence
    ).toEqual(evidence("edge:changed-control", "head"));
  });

  it("caps triage and analysis patches by UTF-8 bytes with an omission marker", () => {
    const { graph, delta } = fixture();
    const largePatch = "😀".repeat(20_000);
    const triagePatch = unwrap(triageInput(delta, largePatch)).patch as string;
    const analysisPatch = unwrap(analysisInput(graph, delta, largePatch)).patch as string;

    expect(Buffer.byteLength(triagePatch, "utf8")).toBeLessThanOrEqual(TRIAGE_PATCH_MAX_BYTES);
    expect(Buffer.byteLength(analysisPatch, "utf8")).toBeLessThanOrEqual(ANALYSIS_PATCH_MAX_BYTES);
    expect(triagePatch.endsWith(PATCH_OMISSION_MARKER)).toBe(true);
    expect(analysisPatch.endsWith(PATCH_OMISSION_MARKER)).toBe(true);
    expect(triagePatch).not.toContain("�");
    expect(analysisPatch).not.toContain("�");
  });

  it("normalizes invalid Unicode without splitting a code point", () => {
    const invalid = `prefix\ud800suffix${"é".repeat(30)}`;
    const result = truncateUtf8(invalid, 64, PATCH_OMISSION_MARKER);

    expect(Buffer.byteLength(result, "utf8")).toBeLessThanOrEqual(64);
    expect(Buffer.from(result, "utf8").toString("utf8")).toBe(result);
    expect(result.endsWith(PATCH_OMISSION_MARKER)).toBe(true);
  });

  it("bounds assumptions and unknowns while making omissions explicit", () => {
    const { graph, delta } = fixture();
    graph.assumptions = Array.from(
      { length: GRAPH_CONTEXT_MAX_ITEMS + 5 },
      (_value, index) => `${index}:${"a".repeat(GRAPH_CONTEXT_ITEM_MAX_BYTES * 2)}`
    );
    graph.unknowns = ["u".repeat(GRAPH_CONTEXT_ITEM_MAX_BYTES * 2)];

    const payload = unwrap(analysisInput(graph, delta, "patch"));
    expect(payload.graph.assumptions).toHaveLength(GRAPH_CONTEXT_MAX_ITEMS);
    expect(payload.graph.assumptions.at(-1)).toBe("[HEDGE_ADDITIONAL_ITEMS_OMITTED]");
    expect(Buffer.byteLength(payload.graph.assumptions[0], "utf8")).toBeLessThanOrEqual(
      GRAPH_CONTEXT_ITEM_MAX_BYTES
    );
    expect(payload.graph.assumptions[0]).toContain("[HEDGE_TEXT_TRUNCATED]");
    expect(Buffer.byteLength(payload.graph.unknowns[0], "utf8")).toBeLessThanOrEqual(
      GRAPH_CONTEXT_ITEM_MAX_BYTES
    );
  });

  it("keeps triage structural and does not send an evidence index", () => {
    const { delta } = fixture();
    const payload = unwrap(triageInput(delta, "patch"));

    expect(payload.evidenceIndex).toBeUndefined();
    expect(payload.delta.addedNodes[0].evidenceRefs).toBeUndefined();
    expect(payload.delta.addedNodes[0].evidenceCount).toBe(1);
    expect(payload.delta.addedNodes[0].controls[0].evidenceCount).toBe(1);
  });
});
