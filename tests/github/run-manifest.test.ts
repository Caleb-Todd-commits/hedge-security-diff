import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  computeRunManifestDigest,
  createRunManifest,
  serializeRunManifest,
  verifyRunBundle,
  type CreateRunManifestOptions,
  type RunManifestBindings
} from "../../src/github/run-manifest.js";

const baseSha = "a".repeat(40);
const headSha = "b".repeat(40);
const digest = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");

const artifacts = {
  "collect/base-graph.json": '{"snapshot":"base"}\n',
  "reason/analysis.json": '{"summary":"bounded"}\n'
};

const metadata: Omit<CreateRunManifestOptions, "createdAt" | "artifacts" | "limits"> = {
  repository: "example/hedge-target",
  pullRequest: 42,
  baseSha,
  headSha,
  workflowRef: "example/hedge-target/.github/workflows/hedge.yml@refs/heads/main",
  actionVersion: "0.5.2+0123456789abcdef",
  extractorVersion: "hedge-next-typescript-extractor-v0.5",
  artifactSchemaVersion: "0.1",
  promptVersion: "hedge-prompt-v0.5",
  configDigest: digest("config"),
  contextDigest: digest("context"),
  extractorDigest: digest("extractor"),
  schemaDigest: digest("schema"),
  promptDigest: digest("prompt"),
  model: "gpt-5.6-sol",
  coverage: {
    status: "complete",
    discoveredFiles: 2,
    includedFiles: 2,
    includedBytes: 240,
    omitted: { fileLimit: 0, byteLimit: 0, unsafeOrUnreadable: 0, binary: 0 },
    diagnostics: []
  },
  analysisHealth: { status: "complete", reasons: [] }
};

const bindings: RunManifestBindings = {
  repository: metadata.repository,
  pullRequest: metadata.pullRequest,
  baseSha,
  headSha,
  workflowRef: metadata.workflowRef,
  actionVersion: metadata.actionVersion
};

function createFixture() {
  return createRunManifest({
    ...metadata,
    createdAt: "2026-07-16T12:00:00.000Z",
    artifacts
  });
}

describe("RunManifest v0.1", () => {
  it("hashes exact artifact bytes and verifies a bound handoff", () => {
    const manifest = createFixture();
    expect(manifest.artifacts["collect/base-graph.json"]).toBe(
      digest(artifacts["collect/base-graph.json"])
    );
    expect(manifest.artifacts["reason/analysis.json"]).toBe(
      digest(artifacts["reason/analysis.json"])
    );
    expect(manifest.manifestDigest).toBe(computeRunManifestDigest(manifest));
    expect(manifest).toMatchObject({
      extractorVersion: "hedge-next-typescript-extractor-v0.5",
      artifactSchemaVersion: "0.1",
      promptVersion: "hedge-prompt-v0.5"
    });

    const verified = verifyRunBundle({
      manifest: serializeRunManifest(manifest),
      artifacts,
      expected: bindings
    });
    expect(verified.manifest).toEqual(manifest);
    expect(verified.totalArtifactBytes).toBe(
      Buffer.byteLength(artifacts["collect/base-graph.json"]) +
        Buffer.byteLength(artifacts["reason/analysis.json"])
    );
  });

  it("rejects tampered and incomplete artifact inventories", () => {
    const manifest = createFixture();
    expect(() =>
      verifyRunBundle({
        manifest,
        artifacts: { ...artifacts, "reason/analysis.json": "tampered" },
        expected: bindings
      })
    ).toThrow(/artifact reason\/analysis\.json digest mismatch/i);

    expect(() =>
      verifyRunBundle({
        manifest,
        artifacts: { "collect/base-graph.json": artifacts["collect/base-graph.json"] },
        expected: bindings
      })
    ).toThrow(/inventory mismatch/i);

    expect(() =>
      verifyRunBundle({
        manifest,
        artifacts: { ...artifacts, "unexpected.json": "{}" },
        expected: bindings
      })
    ).toThrow(/inventory mismatch/i);
  });

  it("rejects tampered manifest metadata even when artifacts are unchanged", () => {
    const manifest = createFixture();
    expect(() =>
      verifyRunBundle({
        manifest: { ...manifest, headSha: "c".repeat(40) },
        artifacts,
        expected: bindings
      })
    ).toThrow(/manifest digest mismatch/i);
  });

  it.each([
    ["repository", { repository: "another/repository" }, /repository binding/i],
    ["pull request", { pullRequest: 41 }, /pull-request binding/i],
    ["base", { baseSha: "c".repeat(40) }, /base-SHA binding/i],
    ["stale head", { headSha: "c".repeat(40) }, /stale/i],
    [
      "workflow",
      { workflowRef: "example/other/.github/workflows/hedge.yml@main" },
      /workflow binding/i
    ],
    ["action", { actionVersion: "0.5.0" }, /action-version binding/i]
  ])("rejects a %s binding mismatch", (_label, changed, message) => {
    expect(() =>
      verifyRunBundle({
        manifest: createFixture(),
        artifacts,
        expected: { ...bindings, ...changed }
      })
    ).toThrow(message as RegExp);
  });

  it("rejects malformed JSON and unknown schema fields", () => {
    expect(() => verifyRunBundle({ manifest: "{", artifacts, expected: bindings })).toThrow(
      /valid JSON/i
    );

    const manifest = createFixture();
    expect(() =>
      verifyRunBundle({
        manifest: { ...manifest, injected: "untrusted" },
        artifacts,
        expected: bindings
      })
    ).toThrow(/unrecognized key/i);
    expect(() =>
      verifyRunBundle({
        manifest: {
          ...manifest,
          coverage: { ...manifest.coverage, injected: "untrusted" }
        },
        artifacts,
        expected: bindings
      })
    ).toThrow(/unrecognized key/i);
  });

  it("rejects manifests whose raw form relies on schema defaults", () => {
    const manifest = JSON.parse(
      Buffer.from(serializeRunManifest(createFixture())).toString("utf8")
    );
    delete manifest.coverage.diagnostics;
    delete manifest.analysisHealth.reasons;

    expect(() =>
      verifyRunBundle({
        manifest: JSON.stringify(manifest),
        artifacts,
        expected: bindings
      })
    ).toThrow(/missing-default|non-canonical/i);
  });

  it.each([
    "../analysis.json",
    "/tmp/analysis.json",
    "reason\\analysis.json",
    "reason//analysis.json",
    "reason/./analysis.json",
    "reason/%2e%2e/analysis.json"
  ])("rejects unsafe artifact path %s", (path) => {
    expect(() =>
      createRunManifest({
        ...metadata,
        artifacts: { [path]: "{}" }
      })
    ).toThrow(/artifact path/i);
  });

  it("enforces manifest, per-artifact, total-byte, and artifact-count limits", () => {
    expect(() =>
      createRunManifest({
        ...metadata,
        artifacts: { "large.json": "12345" },
        limits: { maxArtifactBytes: 4 }
      })
    ).toThrow(/per-artifact limit/i);
    expect(() =>
      createRunManifest({
        ...metadata,
        artifacts: { "one.json": "123", "two.json": "456" },
        limits: { maxTotalArtifactBytes: 5 }
      })
    ).toThrow(/total/i);
    expect(() =>
      createRunManifest({
        ...metadata,
        artifacts: { "one.json": "1", "two.json": "2" },
        limits: { maxArtifacts: 1 }
      })
    ).toThrow(/2 artifacts/i);

    const manifest = createFixture();
    expect(() =>
      verifyRunBundle({
        manifest: JSON.stringify(manifest),
        artifacts,
        expected: bindings,
        limits: { maxManifestBytes: 10 }
      })
    ).toThrow(/manifest is .* limit/i);
  });
});
