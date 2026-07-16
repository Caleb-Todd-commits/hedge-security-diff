import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { format, resolveConfig } from "prettier";
import { z } from "zod";
import {
  AnalysisResultSchema,
  AttackSurfaceGraphSchema,
  CollectionBundleSchema,
  HedgeConfigSchema,
  HedgeContextSchema,
  RunManifestSchema,
  ReasonBundleSchema,
  SecurityInvariantDefinitionSchema,
  ThreatRegisterSchema,
  VerificationEvidenceSchema
} from "../src/domain/schemas.js";

const targets = {
  "attack-surface.schema.json": AttackSurfaceGraphSchema,
  "threat-register.schema.json": ThreatRegisterSchema,
  "hedge-config.schema.json": HedgeConfigSchema,
  "hedge-context.schema.json": HedgeContextSchema,
  "verification-evidence.schema.json": VerificationEvidenceSchema,
  "analysis-result.schema.json": AnalysisResultSchema,
  "run-manifest.schema.json": RunManifestSchema,
  "collection-bundle.schema.json": CollectionBundleSchema,
  "reason-bundle.schema.json": ReasonBundleSchema,
  "security-invariant.schema.json": SecurityInvariantDefinitionSchema
};

const output = resolve("schemas");
const prettierConfig = (await resolveConfig(resolve(".prettierrc.json"))) ?? {};
await mkdir(output, { recursive: true });
for (const [name, schema] of Object.entries(targets)) {
  const json = z.toJSONSchema(schema, { target: "draft-2020-12", unrepresentable: "any" });
  omitRuntimeTimestampDefaults(json);
  const content = await format(
    JSON.stringify({ $schema: "https://json-schema.org/draft/2020-12/schema", ...json }, null, 2),
    { ...prettierConfig, parser: "json" }
  );
  await writeFile(resolve(output, name), content, "utf8");
  console.log(`Wrote schemas/${name}`);
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
