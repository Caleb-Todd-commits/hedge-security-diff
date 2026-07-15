import { describe, expect, it } from "vitest";
import { diffGraphs, hasSecurityArchitectureDelta } from "../../src/graph/diff.js";
import type { AttackSurfaceGraph } from "../../src/domain/schemas.js";

const base: AttackSurfaceGraph = {
  schemaVersion: "0.1",
  generatedAt: "2026-07-13T00:00:00.000Z",
  repository: "test",
  framework: "nextjs",
  nodes: [],
  edges: [],
  assumptions: [],
  unknowns: []
};

describe("graph diff", () => {
  it("detects an added entry point", () => {
    const after: AttackSurfaceGraph = {
      ...base,
      nodes: [
        {
          id: "entrypoint:1",
          kind: "entrypoint",
          label: "POST /api/upload",
          trustZone: "public",
          evidence: [{ file: "app/api/upload/route.ts", line: 1, extractor: "test" }],
          controls: [],
          metadata: { method: "POST" }
        }
      ]
    };
    const delta = diffGraphs(base, after);
    expect(delta.addedNodes).toHaveLength(1);
    expect(hasSecurityArchitectureDelta(delta)).toBe(true);
  });

  it("ignores generated timestamp changes", () => {
    const after = { ...base, generatedAt: "2026-07-14T00:00:00.000Z" };
    expect(hasSecurityArchitectureDelta(diffGraphs(base, after))).toBe(false);
  });
});
