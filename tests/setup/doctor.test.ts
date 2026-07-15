import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { installHedge } from "../../src/setup/install.js";
import { runDoctor } from "../../src/setup/doctor.js";

describe("Hedge doctor", () => {
  it("reports blocking failures for an uninstalled directory", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-doctor-empty-"));
    const result = await runDoctor(root);
    expect(result.healthy).toBe(false);
    expect(
      result.checks.some((check) => check.name === "Hedge configuration" && check.status === "fail")
    ).toBe(true);
    expect(
      result.checks.some(
        (check) => check.name === "Pull request workflow" && check.status === "fail"
      )
    ).toBe(true);
  });

  it("recognizes a structurally installed repository", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-doctor-ready-"));
    await mkdir(join(root, ".git"), { recursive: true });
    await writeFile(join(root, "package.json"), '{"name":"fixture"}\n', "utf8");
    await installHedge({
      root,
      actionRef: "example/hedge@0123456789012345678901234567890123456789"
    });
    const result = await runDoctor(root);
    expect(result.healthy).toBe(true);
    expect(result.checks.find((check) => check.name === "Pinned action reference")?.status).toBe(
      "pass"
    );
    expect(result.checks.find((check) => check.name === "Baseline integrity")?.status).toBe("warn");
  });

  it("fails when a generated workflow still contains an unresolved action placeholder", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-doctor-placeholder-"));
    await mkdir(join(root, ".git"), { recursive: true });
    await writeFile(join(root, "package.json"), '{"name":"fixture"}\n', "utf8");
    await installHedge({
      root,
      actionRef: "example/hedge@0123456789012345678901234567890123456789"
    });
    await writeFile(
      join(root, ".github", "workflows", "hedge-fix.yml"),
      "uses: YOUR_ORG/hedge@PINNED_COMMIT_SHA\n",
      "utf8"
    );
    const result = await runDoctor(root);
    expect(result.healthy).toBe(false);
    expect(result.checks.find((check) => check.name === "Workflow placeholders")?.status).toBe(
      "fail"
    );
  });
});
