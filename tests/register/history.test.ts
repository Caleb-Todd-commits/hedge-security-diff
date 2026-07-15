import { describe, expect, it } from "vitest";
import { emptyRegister, recordRun } from "../../src/register/store.js";

describe("run history", () => {
  it("records and deduplicates architecture runs", () => {
    const register = emptyRegister();
    register.graph = {
      schemaVersion: "0.1",
      generatedAt: "2026-07-14T00:00:00.000Z",
      repository: "test",
      framework: "nextjs",
      nodes: [],
      edges: [],
      assumptions: [],
      unknowns: []
    };
    recordRun(register, { architectureChanged: true, sourceCommit: "abc" });
    recordRun(register, { architectureChanged: true, sourceCommit: "abc" });
    expect(register.runs).toHaveLength(1);
    expect(register.runs[0]!.sourceCommit).toBe("abc");
  });

  it("caps retained run history", () => {
    const register = emptyRegister();
    register.graph = {
      schemaVersion: "0.1",
      generatedAt: "2026-07-14T00:00:00.000Z",
      repository: "test",
      framework: "nextjs",
      nodes: [],
      edges: [],
      assumptions: [],
      unknowns: []
    };
    for (let index = 0; index < 105; index++) {
      recordRun(register, { architectureChanged: index % 2 === 0, sourceCommit: String(index) });
    }
    expect(register.runs).toHaveLength(100);
    expect(register.runs[0]!.sourceCommit).toBe("5");
  });
});
