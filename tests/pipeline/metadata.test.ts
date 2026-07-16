import { describe, expect, it } from "vitest";
import { HedgeConfigSchema, HedgeContextSchema } from "../../src/domain/schemas.js";
import {
  currentActionVersion,
  currentWorkflowRef,
  EXTRACTOR_VERSION,
  PIPELINE_SCHEMA_VERSION,
  PROMPT_VERSION,
  pipelineDigests
} from "../../src/pipeline/metadata.js";

describe("pipeline provenance metadata", () => {
  it("binds exact workflow and Action revisions", () => {
    const workflowSha = "a".repeat(40);
    const actionRef = `example/hedge@${"b".repeat(40)}`;
    expect(
      currentWorkflowRef(
        "example/repository/.github/workflows/hedge.yml@refs/heads/main",
        workflowSha
      )
    ).toBe(`example/repository/.github/workflows/hedge.yml@refs/heads/main#${workflowSha}`);
    expect(currentActionVersion(actionRef)).toBe(`0.5.2+${actionRef}`);
  });

  it("derives stable digests from the current schema and extractor identities", () => {
    const context = HedgeContextSchema.parse({});
    const config = HedgeConfigSchema.parse({ framework: "nextjs" });
    const first = pipelineDigests(config, context);
    const second = pipelineDigests(config, context);

    expect(first).toEqual(second);
    expect(first.schemaDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(first.extractorDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(PIPELINE_SCHEMA_VERSION).toContain("v0.1.2");
    expect(PROMPT_VERSION).toContain("v0.5.3");
    expect(EXTRACTOR_VERSION).toContain("v0.5.2");
    const changed = pipelineDigests(
      HedgeConfigSchema.parse({ framework: "nextjs", fail_on: "critical" }),
      context
    );
    expect(changed.configDigest).not.toBe(first.configDigest);
    expect(changed.schemaDigest).toBe(first.schemaDigest);
  });
});
