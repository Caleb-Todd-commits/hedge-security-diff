import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import YAML from "yaml";

describe("example workflow security contracts", () => {
  it("keeps Codex remediation and publishing in separate jobs", async () => {
    const workflow = YAML.parse(await readFile("examples/workflows/hedge-fix.yml", "utf8"));
    expect(workflow.concurrency.group).toContain("github.event.issue.number");
    expect(workflow.concurrency.group).toContain("github.event.comment.body");
    expect(workflow.concurrency["cancel-in-progress"]).toBe(false);
    expect(workflow.jobs.remediate.permissions.contents).toBe("read");
    expect(workflow.jobs["validate-patch"].permissions.contents).toBe("read");
    expect(workflow.jobs["publish-draft"].permissions.contents).toBe("write");
    expect(JSON.stringify(workflow.jobs["validate-patch"])).not.toContain("OPENAI_API_KEY");
    expect(JSON.stringify(workflow.jobs["publish-draft"])).not.toContain("OPENAI_API_KEY");
  });

  it("runs immutable-witness verification without an OpenAI credential", async () => {
    const text = await readFile("examples/workflows/hedge-verify.yml", "utf8");
    expect(text).not.toContain("OPENAI_API_KEY");
    expect(text).toContain("vulnerableRevisionWitnessSucceeded");
    expect(text).toContain("repairedRevisionWitnessBlocked");
    expect(text).toContain("witnessDigest");
    expect(text).toContain("vulnerableOutcome");
    expect(text).toContain("blocked-by-control");
    expect(text).toContain("graphDeltaDigest");
    expect(text).toContain("architectureEvidence");
    expect(text).toContain("--network none");
    expect(text).not.toContain("architecture_control_changed");
  });
  it("uses trusted base policy while rebuilding exact source graphs when state is absent", async () => {
    const actionSource = await readFile("src/action/index.ts", "utf8");
    const contentSource = await readFile("src/github/content.ts", "utf8");
    expect(actionSource).toContain("trusted.register ?? emptyRegister()");
    expect(actionSource).toContain("baseRevision: requestedBase");
    expect(actionSource).toContain("headRevision: requestedHead");
    expect(actionSource).toContain('writeArtifacts: command !== "collect"');
    expect(contentSource).toContain("ref: options.baseSha");
    expect(contentSource).toContain('path: ".hedge/context.yml"');
    expect(contentSource).toContain('path: "threatmodel.json"');
    expect(contentSource).toContain("the exact base graph will be rebuilt from source");
  });

  it("separates secretless collection, model reasoning, and write-authorized publication", async () => {
    const workflow = YAML.parse(await readFile("examples/workflows/hedge.yml", "utf8"));
    const collect = JSON.stringify(workflow.jobs.collect);
    const reason = JSON.stringify(workflow.jobs.reason);
    const publish = JSON.stringify(workflow.jobs.publish);

    expect(workflow.concurrency["cancel-in-progress"]).toBe(true);
    expect(collect).toContain("actions/checkout@v7");
    expect(collect).toContain('"command":"collect"');
    expect(collect).not.toContain("OPENAI_API_KEY");
    expect(workflow.jobs.collect.permissions["pull-requests"]).toBe("read");

    expect(reason).toContain("OPENAI_API_KEY");
    expect(reason).toContain('"command":"reason"');
    expect(reason).not.toContain("actions/checkout");
    expect(reason).not.toContain("github-token");
    expect(workflow.jobs.reason.permissions).toEqual({});

    expect(publish).toContain('"command":"publish"');
    expect(publish).not.toContain("OPENAI_API_KEY");
    expect(publish).not.toContain("actions/checkout");
    expect(workflow.jobs.publish.permissions["pull-requests"]).toBe("write");

    const reasonUpload = workflow.jobs.reason.steps.find(
      (step: { name?: string }) => step.name === "Upload validated reasoning bundle"
    );
    expect(reasonUpload.with.path).toContain("reason-bundle-path");
    expect(reasonUpload.with.path).not.toContain("collection-path");
    const publishDownloads = workflow.jobs.publish.steps.filter(
      (step: { uses?: string }) => step.uses === "actions/download-artifact@v8"
    );
    expect(publishDownloads.map((step: { with: { name: string } }) => step.with.name)).toEqual([
      "hedge-collection-${{ github.run_id }}",
      "hedge-reason-${{ github.run_id }}"
    ]);
    expect(JSON.stringify(workflow.jobs.collect)).toContain("${{ runner.temp }}/hedge-collection");
    expect(JSON.stringify(workflow.jobs.reason)).toContain("${{ runner.temp }}/hedge-reason");
    for (const jobName of ["collect", "reason", "publish"]) {
      const actionStep = workflow.jobs[jobName].steps.find(
        (step: { uses?: string }) => step.uses === "YOUR_ORG/hedge@PINNED_COMMIT_SHA"
      );
      expect(actionStep.with["workflow-sha"]).toBe("${{ github.workflow_sha }}");
      expect(actionStep.with["action-ref"]).toBe("YOUR_ORG/hedge@PINNED_COMMIT_SHA");
    }

    for (const [name, job] of Object.entries(workflow.jobs as Record<string, unknown>)) {
      const serialized = JSON.stringify(job);
      const hasModelCredential = serialized.includes("OPENAI_API_KEY");
      const hasWriteAuthority = /\"(?:contents|pull-requests)\":\"write\"/.test(serialized);
      expect(hasModelCredential && hasWriteAuthority, name).toBe(false);
    }
  });

  it("does not let Action metadata defaults silently override repository model policy", async () => {
    const action = YAML.parse(await readFile("action.yml", "utf8"));
    expect(action.inputs["model-triage"].default).toBeUndefined();
    expect(action.inputs["model-analysis"].default).toBeUndefined();
    expect(action.inputs["github-token"].default).toBeUndefined();
  });

  it("rejects a legacy pull-request check that combines model and GitHub credentials", async () => {
    const actionSource = await readFile("src/action/index.ts", "utf8");
    expect(actionSource).toContain(
      'command === "check" && pullRequest && configuredApiKey && githubToken'
    );
    expect(actionSource).toContain(
      "Pull-request check refuses to combine an OpenAI credential with GitHub authority"
    );
  });

  it("does not publish SARIF from a stale or otherwise rejected publisher run", async () => {
    const workflow = await readFile("examples/workflows/hedge.yml", "utf8");
    expect(workflow).toContain("steps.hedge.outputs.analysis-path != ''");
    const actionSource = await readFile("src/action/index.ts", "utf8");
    expect(actionSource).toContain("reason refuses to run in a job that exposes a GitHub token");
  });
  it("persists verification and acceptance through the published action", async () => {
    const action = YAML.parse(await readFile("action.yml", "utf8"));
    expect(action.inputs["risk-id"]).toBeDefined();
    expect(action.inputs["verification-evidence"]).toBeDefined();
    expect(action.inputs["architecture-control-changed"]).toBeUndefined();
    expect(action.inputs["acceptance-reason"]).toBeDefined();

    const verification = await readFile("examples/workflows/hedge-verify.yml", "utf8");
    expect(verification).toContain("command: verify");
    expect(verification).toContain("Open one reviewable verification-state PR");
    const prune = await readFile("examples/workflows/hedge-prune.yml", "utf8");
    expect(prune).toContain("command: prune");
    expect(prune).not.toContain("npx hedge-action");
  });

  it("publishes both standalone and GitHub-native report artifacts", async () => {
    const workflow = await readFile("examples/workflows/hedge.yml", "utf8");
    expect(workflow).toContain("html-report-path");
    expect(workflow).toContain("results.sarif");
    expect(workflow).toContain("upload-sarif@v4");
  });
  it("binds Codex remediation to an integrity-checked report for the current PR head", async () => {
    const workflow = await readFile("examples/workflows/hedge-fix.yml", "utf8");
    expect(workflow).toContain("payloadDigest");
    expect(workflow).toContain("actualDigest");
    expect(workflow).toContain("payload.sourceCommit !== pr.data.head.sha");
    expect(workflow).toContain("latest Hedge report is stale");
  });

  it("passes risk-acceptance reasons as base64 instead of multiline workflow output", async () => {
    const workflow = await readFile("examples/workflows/hedge-prune.yml", "utf8");
    expect(workflow).toContain("acceptance-reason-b64");
    expect(workflow).not.toContain("EOF_REASON");
    expect(workflow).not.toContain("base64 --decode");
  });

  it("resolves verification refs to exact commits and serializes evidence safely", async () => {
    const workflow = await readFile("examples/workflows/hedge-verify.yml", "utf8");
    expect(workflow).toContain("repos.getCommit");
    expect(workflow).toContain("vulnerableSha === repairedSha");
    expect(workflow).toContain("JSON.stringify(evidence, null, 2)");
    expect(workflow).not.toContain("<<EOF_JSON");
  });

  it("treats witness crashes and malformed output as inconclusive", async () => {
    const workflow = await readFile("examples/workflows/hedge-verify.yml", "utf8");
    expect(workflow).toContain("let outcome = 'inconclusive'");
    expect(workflow).toContain("process failures are inconclusive");
    expect(workflow).toContain("vulnerableOutcome: vulnerable.outcome");
    expect(workflow).toContain("outcome === 'blocked-by-control'");
  });

  it("validates remediation patches before a separate write-authorized publisher", async () => {
    const workflow = await readFile("examples/workflows/hedge-fix.yml", "utf8");
    expect(workflow).toContain("Remediation patch exceeds 256 KiB");
    expect(workflow).toContain("Protected patch path");
    expect(workflow).toContain("Generated or dependency state is not allowed");
    expect(workflow).toContain("summaryDigest");
    expect(workflow).toContain("Symlink and submodule patches are not allowed");
    expect(workflow).toContain("git apply --check");
    expect(workflow).toContain("needs.validate-patch.result == 'success'");
    expect(workflow).toContain("Pull-request head changed after remediation authorization");
    expect(workflow).toContain("draft: true");
    expect(workflow).not.toContain("${FINAL_MESSAGE}");
  });
});
