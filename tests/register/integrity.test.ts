import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeWithHeuristics } from "../../src/analysis/heuristics.js";
import { stableHash } from "../../src/utils/hash.js";
import type { GraphDelta } from "../../src/domain/schemas.js";
import {
  bindThreatRegisterState,
  emptyRegister,
  loadThreatRegister,
  saveThreatRegister,
  mergeFindings,
  validateThreatRegisterIntegrity
} from "../../src/register/store.js";

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

describe("threat register integrity", () => {
  it("detects tampering with findings and acceptance history, not only the graph", () => {
    const register = emptyRegister();
    register.graph = {
      schemaVersion: "0.1",
      generatedAt: "2026-07-14T00:00:00.000Z",
      repository: "test",
      framework: "nextjs",
      nodes: delta.addedNodes,
      edges: [],
      assumptions: [],
      unknowns: []
    };
    mergeFindings(register, analyzeWithHeuristics(delta));
    bindThreatRegisterState(register, { sourceCommit: "abc123" });
    expect(validateThreatRegisterIntegrity(register)).toEqual([]);

    register.findings[0]!.title = "tampered title";
    expect(
      validateThreatRegisterIntegrity(register).some((warning) =>
        warning.includes("register digest")
      )
    ).toBe(true);
  });

  it("detects tampering with persisted invariant evaluations", () => {
    const register = emptyRegister();
    register.graph = {
      schemaVersion: "0.1",
      generatedAt: "2026-07-14T00:00:00.000Z",
      repository: "test",
      framework: "nextjs",
      nodes: delta.addedNodes,
      edges: [],
      assumptions: [],
      unknowns: []
    };
    register.invariantEvaluations = [
      {
        invariantId: "INV-001",
        description: "Public mutations require authentication.",
        severity: "high",
        status: "satisfied",
        matchedNodeIds: ["entrypoint:1"],
        missingControls: [],
        evidence: delta.addedNodes[0]!.evidence,
        reason: "Required controls were detected."
      }
    ];
    bindThreatRegisterState(register, { sourceCommit: "abc123" });
    expect(validateThreatRegisterIntegrity(register)).toEqual([]);
    register.invariantEvaluations[0]!.status = "violated";
    expect(validateThreatRegisterIntegrity(register).join(" ")).toContain("register digest");
  });

  it("accepts a legacy graph-bound register once and upgrades it on save", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-legacy-state-"));
    const register = emptyRegister();
    register.graph = {
      schemaVersion: "0.1",
      generatedAt: "2026-07-14T00:00:00.000Z",
      repository: "legacy",
      framework: "nextjs",
      nodes: delta.addedNodes,
      edges: [],
      assumptions: [],
      unknowns: []
    };
    bindThreatRegisterState(register, { sourceCommit: "legacy" });
    register.stateIntegrity!.algorithm = undefined;
    register.stateIntegrity!.registerHash = "digest-from-an-older-serializer";
    const { writeFile } = await import("node:fs/promises");
    await writeFile(
      join(root, "threatmodel.json"),
      `${JSON.stringify(register, null, 2)}\n`,
      "utf8"
    );

    const loaded = await loadThreatRegister(root);
    expect(loaded.stateIntegrity?.algorithm).toBeUndefined();
    await saveThreatRegister(root, loaded);
    const upgraded = await loadThreatRegister(root);
    expect(upgraded.stateIntegrity?.algorithm).toBe("sha256-stable-json-v2");
    expect(validateThreatRegisterIntegrity(upgraded)).toEqual([]);
  });
  it("migrates a valid v0.4 register whose digest predates invariant state", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-v04-state-"));
    const register = emptyRegister();
    register.graph = {
      schemaVersion: "0.1",
      generatedAt: "2026-07-14T00:00:00.000Z",
      repository: "legacy-v04",
      framework: "nextjs",
      nodes: delta.addedNodes,
      edges: [],
      assumptions: [],
      unknowns: []
    };
    mergeFindings(register, analyzeWithHeuristics(delta));
    bindThreatRegisterState(register, { sourceCommit: "legacy-v04" });
    register.stateIntegrity!.toolVersion = "0.4.0";
    register.stateIntegrity!.registerHash = stableHash(
      {
        schemaVersion: register.schemaVersion,
        nextRiskNumber: register.nextRiskNumber,
        graph: register.graph,
        findings: register.findings,
        runs: register.runs,
        acceptedRisks: register.acceptedRisks
      },
      64
    );

    const raw = JSON.parse(JSON.stringify(register)) as Record<string, unknown>;
    delete raw.invariantEvaluations;
    const { writeFile } = await import("node:fs/promises");
    await writeFile(join(root, "threatmodel.json"), `${JSON.stringify(raw, null, 2)}\n`, "utf8");

    const loaded = await loadThreatRegister(root);
    expect(loaded.stateIntegrity?.toolVersion).toBe("0.4.0");
    await saveThreatRegister(root, loaded);
    const upgraded = await loadThreatRegister(root);
    expect(upgraded.stateIntegrity?.toolVersion).toBe("0.5.0");
    expect(upgraded.invariantEvaluations ?? []).toEqual([]);
    expect(validateThreatRegisterIntegrity(upgraded)).toEqual([]);
  });
});
