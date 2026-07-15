import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import YAML from "yaml";
import { installHedge } from "../../src/setup/install.js";

describe("Hedge installer", () => {
  it("installs a minimal trusted PR workflow and configuration", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-install-"));
    const result = await installHedge({
      root,
      actionRef: "example/hedge@0123456789012345678901234567890123456789"
    });

    expect(result.skipped).toEqual([]);
    expect(result.written).toContain(".hedge.yml");
    expect(result.written).toContain(".hedge/context.yml");
    expect(result.written).toContain(".github/workflows/hedge.yml");

    const workflowText = await readFile(join(root, ".github/workflows/hedge.yml"), "utf8");
    const workflow = YAML.parse(workflowText);
    expect(workflow.jobs.hedge.permissions).toBeUndefined();
    expect(workflow.permissions.contents).toBe("read");
    expect(workflow.permissions["pull-requests"]).toBe("write");
    expect(workflow.permissions["security-events"]).toBe("write");
    expect(workflowText).toContain("example/hedge@0123456789012345678901234567890123456789");
    expect(workflowText).toContain("upload-sarif");
  });

  it("does not overwrite existing repository policy unless forced", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-install-existing-"));
    await mkdir(root, { recursive: true });
    await writeFile(join(root, ".hedge.yml"), "framework: nextjs\n", "utf8");

    const result = await installHedge({
      root,
      actionRef: "example/hedge@v0.4.0"
    });
    expect(result.skipped).toContain(".hedge.yml");
    expect(await readFile(join(root, ".hedge.yml"), "utf8")).toBe("framework: nextjs\n");
  });

  it("installs the complete reviewable workflow set", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-install-full-"));
    const result = await installHedge({
      root,
      actionRef: "example/hedge@v0.4.0",
      full: true
    });

    expect(result.written).toEqual(
      expect.arrayContaining([
        ".github/workflows/hedge-fix.yml",
        ".github/workflows/hedge-verify.yml",
        ".github/workflows/hedge-refresh.yml",
        ".github/workflows/hedge-prune.yml"
      ])
    );
    const prune = await readFile(join(root, ".github/workflows/hedge-prune.yml"), "utf8");
    const fix = await readFile(join(root, ".github/workflows/hedge-fix.yml"), "utf8");
    const verify = await readFile(join(root, ".github/workflows/hedge-verify.yml"), "utf8");
    expect(prune).toContain("@hedge\\s+prune");
    expect(prune).toContain("acceptance-reason-b64");
    expect(prune).not.toContain("EOF_REASON");
    expect(fix).toContain("payload.sourceCommit !== pr.data.head.sha");
    expect(verify).toContain("example/hedge@v0.4.0");
    expect(`${fix}\n${verify}\n${prune}`).not.toContain("PINNED_COMMIT_SHA");
    expect(prune).toContain('git commit -m "chore: accept ${RISK_ID}"');
  });

  it("rejects malformed action references", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-install-ref-"));
    await expect(installHedge({ root, actionRef: "latest" })).rejects.toThrow(
      "owner/repository@immutable-ref"
    );
  });
});
