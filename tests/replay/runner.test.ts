import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runReplay } from "../../src/replay/runner.js";

async function write(path: string, value: string): Promise<void> {
  await mkdir(join(path, ".."), { recursive: true });
  await writeFile(path, value);
}

describe("end-to-end replay harness", () => {
  it("replays base to head through extraction, invariant evaluation, decisions, and reports", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "hedge-replay-fixture-"));
    await mkdir(join(fixture, "base"), { recursive: true });
    await mkdir(join(fixture, "head", "app", "api", "files", "upload"), { recursive: true });
    await writeFile(join(fixture, "base", "package.json"), '{"name":"base"}\n');
    await writeFile(join(fixture, "head", "package.json"), '{"name":"head"}\n');
    await writeFile(
      join(fixture, "head", "app", "api", "files", "upload", "route.ts"),
      `export async function POST(request: Request) {\n  const body = await request.formData();\n  await prisma.file.create({ data: { name: String(body.get("name")) } });\n  return Response.json({ ok: true });\n}\n`
    );
    await writeFile(
      join(fixture, "replay.json"),
      JSON.stringify(
        {
          schemaVersion: "0.1",
          name: "upload-invariant",
          repository: "test/replay",
          config: {
            framework: "nextjs",
            fail_on: "high",
            invariants: [
              {
                id: "INV-UPLOAD",
                description: "Public upload routes require authentication and a size limit.",
                severity: "high",
                applies_to: { label_pattern: "* /api/files/*" },
                requires: { controls: ["authentication", "size-limit"] },
                rationale: "Anonymous unbounded uploads can consume storage."
              }
            ]
          },
          expected: {
            surfaceChanged: true,
            decision: "block",
            minFindings: 1,
            observationKindsInclude: ["node-added", "invariant-evaluated"],
            invariantStatuses: { "INV-UPLOAD": "violated" }
          }
        },
        null,
        2
      )
    );

    const output = join(fixture, "actual");
    const result = await runReplay(fixture, output);
    expect(result.passed, result.failures.join("\n")).toBe(true);
    expect(result.findingCount).toBeGreaterThan(0);
    expect(result.outputDirectory).toBe(output);
  });
});
