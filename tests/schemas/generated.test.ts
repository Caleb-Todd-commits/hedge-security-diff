import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

const names = [
  "attack-surface.schema.json",
  "threat-register.schema.json",
  "hedge-config.schema.json",
  "hedge-context.schema.json",
  "verification-evidence.schema.json",
  "analysis-result.schema.json",
  "security-invariant.schema.json"
];

describe("published JSON schemas", () => {
  for (const name of names) {
    it(`${name} is valid Draft 2020-12 JSON`, async () => {
      const schema = JSON.parse(await readFile(`schemas/${name}`, "utf8")) as Record<
        string,
        unknown
      >;
      expect(schema.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
      expect(schema.type).toBe("object");
    });
  }

  it("does not publish runtime-generated timestamp defaults", async () => {
    for (const name of names) {
      const schema = JSON.parse(await readFile(`schemas/${name}`, "utf8")) as unknown;
      expect(findRecordedAtDefaults(schema), name).toEqual([]);
    }
  });
});

function findRecordedAtDefaults(value: unknown, path = "$", matches: string[] = []): string[] {
  if (Array.isArray(value)) {
    value.forEach((item, index) => findRecordedAtDefaults(item, `${path}[${index}]`, matches));
    return matches;
  }
  if (!value || typeof value !== "object") return matches;

  const record = value as Record<string, unknown>;
  const properties = record.properties;
  if (properties && typeof properties === "object" && !Array.isArray(properties)) {
    const recordedAt = (properties as Record<string, unknown>).recordedAt;
    if (
      recordedAt &&
      typeof recordedAt === "object" &&
      !Array.isArray(recordedAt) &&
      Object.hasOwn(recordedAt, "default")
    ) {
      matches.push(`${path}.properties.recordedAt.default`);
    }
  }
  for (const [key, child] of Object.entries(record)) {
    findRecordedAtDefaults(child, `${path}.${key}`, matches);
  }
  return matches;
}
