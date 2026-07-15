import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { z } from "zod";
import {
  AnalysisResultSchema,
  AttackSurfaceGraphSchema,
  HedgeConfigSchema,
  HedgeContextSchema,
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
  "security-invariant.schema.json": SecurityInvariantDefinitionSchema
};

const output = resolve("schemas");
await mkdir(output, { recursive: true });
for (const [name, schema] of Object.entries(targets)) {
  const json = z.toJSONSchema(schema, { target: "draft-2020-12", unrepresentable: "any" });
  await writeFile(
    resolve(output, name),
    `${JSON.stringify({ $schema: "https://json-schema.org/draft/2020-12/schema", ...json }, null, 2)}\n`,
    "utf8"
  );
  console.log(`Wrote schemas/${name}`);
}
