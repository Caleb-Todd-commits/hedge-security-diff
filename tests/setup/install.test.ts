import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import YAML from "yaml";
import { installHedge } from "../../src/setup/install.js";

describe("Hedge installer", () => {
  afterEach(() => vi.restoreAllMocks());

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
    expect(workflow.permissions.contents).toBe("read");
    expect(workflow.jobs.collect.permissions["pull-requests"]).toBe("read");
    expect(workflow.jobs.reason.permissions).toEqual({});
    expect(
      workflow.jobs.reason.steps.some((step: { uses?: string }) => step.uses?.includes("checkout"))
    ).toBe(false);
    expect(workflow.jobs.publish.permissions["pull-requests"]).toBe("write");
    expect(workflow.jobs.publish.permissions["security-events"]).toBe("write");
    expect(workflowText).toContain("example/hedge@0123456789012345678901234567890123456789");
    expect(workflowText).not.toContain("PINNED_COMMIT_SHA");
    for (const jobName of ["collect", "reason", "publish"]) {
      const actionStep = workflow.jobs[jobName].steps.find((step: { uses?: string }) =>
        step.uses?.startsWith("example/hedge@")
      );
      expect(actionStep.with["action-ref"]).toBe(
        "example/hedge@0123456789012345678901234567890123456789"
      );
    }
    expect(workflowText).toContain("command: collect");
    expect(workflowText).toContain("command: reason");
    expect(workflowText).toContain("command: publish");
    expect(workflowText).toContain("upload-sarif");
  });

  it("does not overwrite existing repository policy unless forced", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-install-existing-"));
    await mkdir(root, { recursive: true });
    await writeFile(join(root, ".hedge.yml"), "framework: nextjs\n", "utf8");

    const result = await installHedge({
      root,
      actionRef: "example/hedge@0123456789012345678901234567890123456789"
    });
    expect(result.skipped).toContain(".hedge.yml");
    expect(await readFile(join(root, ".hedge.yml"), "utf8")).toBe("framework: nextjs\n");
  });

  it("installs the complete reviewable workflow set", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-install-full-"));
    const result = await installHedge({
      root,
      actionRef: "example/hedge@0123456789012345678901234567890123456789",
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
    expect(verify).toContain("example/hedge@0123456789012345678901234567890123456789");
    expect(`${fix}\n${verify}\n${prune}`).not.toContain("PINNED_COMMIT_SHA");
    expect(prune).toContain('git commit -m "chore: accept ${RISK_ID}"');
  });

  it("rejects malformed action references", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-install-ref-"));
    await expect(installHedge({ root, actionRef: "latest" })).rejects.toThrow(
      "owner/repository@ followed by a full commit SHA"
    );
  });

  it("rejects mutable action tags and branches", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-install-mutable-ref-"));
    await expect(installHedge({ root, actionRef: "example/hedge@v0.5.2" })).rejects.toThrow(
      "full commit SHA"
    );
    await expect(installHedge({ root, actionRef: "example/hedge@main" })).rejects.toThrow(
      "full commit SHA"
    );
  });

  it("loads complete workflow assets without depending on the caller working directory", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-install-cwd-independent-"));
    vi.spyOn(process, "cwd").mockReturnValue("/path/that/does/not/contain/hedge");

    await installHedge({
      root,
      actionRef: "example/hedge@0123456789012345678901234567890123456789",
      full: true
    });

    const fix = await readFile(join(root, ".github/workflows/hedge-fix.yml"), "utf8");
    const verify = await readFile(join(root, ".github/workflows/hedge-verify.yml"), "utf8");
    expect(fix).toContain("Hedge Codex remediation");
    expect(verify).toContain("Hedge counterfactual verification");
  });
});
