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
});
