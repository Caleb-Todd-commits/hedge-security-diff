import { describe, expect, it } from "vitest";
import { HedgeConfigSchema, HedgeContextSchema } from "../../src/domain/schemas.js";
import { stableHash } from "../../src/utils/hash.js";
import {
  bindThreatRegisterState,
  emptyRegister,
  validateThreatRegisterBindings
} from "../../src/register/store.js";

describe("baseline policy bindings", () => {
  it("detects policy, context, and source revision drift", () => {
    const register = emptyRegister();
    register.graph = {
      schemaVersion: "0.1",
      generatedAt: "2026-07-14T00:00:00.000Z",
      repository: "test",
      framework: "nextjs",
      nodes: [],
      edges: [],
      assumptions: [],
      unknowns: []
    };
    const config = HedgeConfigSchema.parse({ framework: "nextjs" });
    const context = HedgeContextSchema.parse({ sensitive_assets: ["Invoices"] });
    bindThreatRegisterState(register, {
      configHash: undefined,
      contextHash: undefined,
      sourceCommit: "base-a"
    });
    bindThreatRegisterState(register, {
      configHash: stableHash(config, 64),
      contextHash: stableHash(context, 64),
      sourceCommit: "base-a"
    });
    expect(
      validateThreatRegisterBindings(register, { config, context, sourceCommit: "base-a" })
    ).toEqual([]);
    const changed = HedgeConfigSchema.parse({ framework: "express" });
    const warnings = validateThreatRegisterBindings(register, {
      config: changed,
      context: HedgeContextSchema.parse({ sensitive_assets: ["User profiles"] }),
      sourceCommit: "base-b"
    });
    expect(warnings).toHaveLength(3);
  });
});
