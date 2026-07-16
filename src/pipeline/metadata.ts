import { z } from "zod";
import {
  AnalysisResultSchema,
  CollectionBundleSchema,
  ReasonBundleSchema,
  RunManifestSchema,
  type HedgeConfig,
  type HedgeContext
} from "../domain/schemas.js";
import { analysisSystemPrompt, triageSystemPrompt } from "../model/prompts.js";
import { stableHash } from "../utils/hash.js";
import { HEDGE_VERSION } from "../version.js";

export const PIPELINE_SCHEMA_VERSION = "hedge-pipeline-schema-v0.1.1";
export const PROMPT_VERSION = "hedge-prompt-v0.5.2";
export const EXTRACTOR_VERSION = "hedge-next-typescript-extractor-v0.5.2";

export function currentActionVersion(explicitActionRef?: string): string {
  const actionRef = explicitActionRef?.trim() || process.env.HEDGE_ACTION_REF?.trim();
  return actionRef ? `${HEDGE_VERSION}+${actionRef}` : HEDGE_VERSION;
}

export function currentWorkflowRef(explicitRef?: string, explicitSha?: string): string {
  const workflowRef = explicitRef?.trim() || process.env.GITHUB_WORKFLOW_REF?.trim();
  const workflowSha = explicitSha?.trim() || process.env.GITHUB_WORKFLOW_SHA?.trim();
  if (workflowRef && workflowSha) return `${workflowRef}#${workflowSha.toLowerCase()}`;
  if (workflowRef && !process.env.GITHUB_ACTIONS) return workflowRef;
  return "local/workflow@local";
}

export function pipelineDigests(
  config: HedgeConfig,
  context: HedgeContext
): {
  configDigest: string;
  contextDigest: string;
  extractorDigest: string;
  schemaDigest: string;
  promptDigest: string;
} {
  const schemas = pipelineSchemaIdentity();
  const schemaDigest = stableHash(schemas, 64);
  return {
    configDigest: stableHash(config, 64),
    contextDigest: stableHash(context, 64),
    extractorDigest: stableHash(
      {
        extractor: EXTRACTOR_VERSION,
        hedgeVersion: HEDGE_VERSION,
        schemaDigest
      },
      64
    ),
    schemaDigest,
    promptDigest: stableHash(
      {
        version: PROMPT_VERSION,
        triage: triageSystemPrompt(),
        analysis: analysisSystemPrompt()
      },
      64
    )
  };
}

function pipelineSchemaIdentity(): Record<string, unknown> {
  const schemas: Record<string, unknown> = {
    version: PIPELINE_SCHEMA_VERSION,
    collection: z.toJSONSchema(CollectionBundleSchema, {
      target: "draft-2020-12",
      unrepresentable: "any"
    }),
    reason: z.toJSONSchema(ReasonBundleSchema, {
      target: "draft-2020-12",
      unrepresentable: "any"
    }),
    runManifest: z.toJSONSchema(RunManifestSchema, {
      target: "draft-2020-12",
      unrepresentable: "any"
    }),
    analysis: z.toJSONSchema(AnalysisResultSchema, {
      target: "draft-2020-12",
      unrepresentable: "any"
    })
  };
  omitRuntimeTimestampDefaults(schemas);
  return schemas;
}

function omitRuntimeTimestampDefaults(value: unknown): void {
  if (Array.isArray(value)) {
    for (const item of value) omitRuntimeTimestampDefaults(item);
    return;
  }
  if (!value || typeof value !== "object") return;
  const record = value as Record<string, unknown>;
  const properties = record.properties;
  if (properties && typeof properties === "object" && !Array.isArray(properties)) {
    const recordedAt = (properties as Record<string, unknown>).recordedAt;
    if (recordedAt && typeof recordedAt === "object" && !Array.isArray(recordedAt)) {
      delete (recordedAt as Record<string, unknown>).default;
    }
  }
  for (const child of Object.values(record)) omitRuntimeTimestampDefaults(child);
}
