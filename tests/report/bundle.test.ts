import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseConfigText } from "../../src/config/load.js";
import { checkHedge, initializeHedge } from "../../src/core/run.js";
import { createProofBundle, verifyProofBundle } from "../../src/report/bundle.js";

describe("proof bundle", () => {
  it("copies reports and verifies their digest manifest", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-proof-"));
    const route = join(root, "app", "api", "users");
    await mkdir(route, { recursive: true });
    await writeFile(
      join(route, "route.ts"),
      "export async function GET(){ return Response.json([]); }\n"
    );
    const config = parseConfigText("framework: nextjs\n");
    await initializeHedge(root, config, "example/proof");
    await checkHedge({
      root,
      config,
      baselineRegister: {
        schemaVersion: "0.1",
        generatedAt: new Date().toISOString(),
        nextRiskNumber: 1,
        findings: [],
        runs: [],
        acceptedRisks: []
      }
    });

    const bundle = await createProofBundle({
      root,
      repository: "example/proof",
      baseRef: "base",
      headRef: "head"
    });
    expect(bundle.manifest.files.length).toBeGreaterThanOrEqual(4);
    expect(bundle.manifest.manifestDigest).toHaveLength(64);
    await expect(verifyProofBundle(bundle.manifestPath)).resolves.toEqual([]);

    const first = bundle.manifest.files[0]!;
    await writeFile(join(bundle.directory, first.bundledAs), "tampered\n", "utf8");
    const warnings = await verifyProofBundle(bundle.manifestPath);
    expect(warnings.some((warning) => warning.includes("Digest mismatch"))).toBe(true);
  });

  it("does not copy reviewed configuration or context into the proof artifact", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-proof-private-"));
    await writeFile(join(root, ".hedge.yml"), "framework: auto\n", "utf8");
    await mkdir(join(root, ".hedge"), { recursive: true });
    await writeFile(
      join(root, ".hedge", "context.yml"),
      "notes:\n  - private architecture detail\n",
      "utf8"
    );
    await initializeHedge(root, parseConfigText("framework: auto\n"));
    const bundle = await createProofBundle({ root });
    const text = await readFile(bundle.manifestPath, "utf8");
    expect(text).not.toContain("private architecture detail");
    expect(bundle.manifest.state.configHash).toHaveLength(64);
    expect(bundle.manifest.state.contextHash).toHaveLength(64);
  });
});
