import { describe, expect, it } from "vitest";
import { zodTextFormat } from "openai/helpers/zod";
import { ModelAnalysisSchema, TriageResultSchema } from "../../src/model/schemas.js";

interface JsonSchemaObject {
  type?: string;
  properties?: Record<string, JsonSchemaObject>;
  required?: string[];
  additionalProperties?: boolean;
  items?: JsonSchemaObject;
  anyOf?: JsonSchemaObject[];
  maxItems?: number;
  maxLength?: number;
}

describe("model Structured Output schemas", () => {
  it("keeps triage to one required boolean", () => {
    const format = zodTextFormat(TriageResultSchema, "hedge_triage");
    const schema = format.schema as JsonSchemaObject;

    expect(format.strict).toBe(true);
    expect(schema.required).toEqual(["deepAnalysisRequired"]);
    expect(Object.keys(schema.properties ?? {})).toEqual(["deepAnalysisRequired"]);
    expect(schema.additionalProperties).toBe(false);

    expect(
      TriageResultSchema.parse({
        deepAnalysisRequired: false,
        reason: "legacy recorded field",
        categories: ["none"]
      })
    ).toEqual({ deepAnalysisRequired: false });
  });

  it("requires every object property and represents optional transport values as nullable", () => {
    const format = zodTextFormat(ModelAnalysisSchema, "hedge_analysis");
    const schema = format.schema as JsonSchemaObject;

    expect(format.strict).toBe(true);
    expectObjectPropertiesRequired(schema);
    expect(schema.properties?.findings?.maxItems).toBe(3);

    const proposal = schema.properties?.findings?.items;
    expect(proposal?.properties?.title?.maxLength).toBe(160);
    expect(proposal?.properties?.suggestedTest?.anyOf).toEqual(
      expect.arrayContaining([expect.objectContaining({ type: "null" })])
    );
    expect(proposal?.properties?.remediationPrompt?.anyOf).toEqual(
      expect.arrayContaining([expect.objectContaining({ type: "null" })])
    );
  });
});

function expectObjectPropertiesRequired(schema: JsonSchemaObject): void {
  if (schema.properties) {
    expect(schema.additionalProperties).toBe(false);
    expect(new Set(schema.required)).toEqual(new Set(Object.keys(schema.properties)));
    Object.values(schema.properties).forEach(expectObjectPropertiesRequired);
  }
  if (schema.items) expectObjectPropertiesRequired(schema.items);
  schema.anyOf?.forEach(expectObjectPropertiesRequired);
}
