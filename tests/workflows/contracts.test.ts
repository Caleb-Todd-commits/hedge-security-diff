import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import YAML from "yaml";

describe("example workflow security contracts", () => {
  it("keeps Codex remediation and publishing in separate jobs", async () => {
    const workflow = YAML.parse(await readFile("examples/workflows/hedge-fix.yml", "utf8"));
    expect(workflow.jobs.remediate.permissions.contents).toBe("read");
    expect(workflow.jobs["publish-draft"].permissions.contents).toBe("write");
    expect(JSON.stringify(workflow.jobs["publish-draft"])).not.toContain("OPENAI_API_KEY");
  });

  it("runs verification without an OpenAI credential", async () => {
    const text = await readFile("examples/workflows/hedge-verify.yml", "utf8");
    expect(text).not.toContain("OPENAI_API_KEY");
    expect(text).toContain("vulnerableRevisionWitnessSucceeded");
    expect(text).toContain("repairedRevisionWitnessBlocked");
  });
  it("uses trusted base policy and an explicit empty baseline when state is absent", async () => {
    const actionSource = await readFile("src/action/index.ts", "utf8");
    const contentSource = await readFile("src/github/content.ts", "utf8");
    expect(actionSource).toContain("trusted.register ?? emptyRegister()");
    expect(contentSource).toContain("ref: options.baseSha");
    expect(contentSource).toContain('path: ".hedge/context.yml"');
    expect(contentSource).toContain('path: "threatmodel.json"');
  });

  it("does not let Action metadata defaults silently override repository model policy", async () => {
    const action = YAML.parse(await readFile("action.yml", "utf8"));
    expect(action.inputs["model-triage"].default).toBeUndefined();
    expect(action.inputs["model-analysis"].default).toBeUndefined();
  });
  it("persists verification and acceptance through the published action", async () => {
    const action = YAML.parse(await readFile("action.yml", "utf8"));
    expect(action.inputs["risk-id"]).toBeDefined();
    expect(action.inputs["verification-evidence"]).toBeDefined();
    expect(action.inputs["architecture-control-changed"]).toBeDefined();
    expect(action.inputs["acceptance-reason"]).toBeDefined();

    const verification = await readFile("examples/workflows/hedge-verify.yml", "utf8");
    expect(verification).toContain("command: verify");
    expect(verification).toContain("Open reviewable verification-state PR");
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

  it("validates verification refs and serializes evidence with JSON.stringify", async () => {
    const workflow = await readFile("examples/workflows/hedge-verify.yml", "utf8");
    expect(workflow).toContain('[[ "$REF" =~ ^[A-Za-z0-9]');
    expect(workflow).toContain("JSON.stringify(evidence, null, 2)");
    expect(workflow).not.toContain("<<EOF_JSON");
  });
});
