import { describe, expect, it } from "vitest";
import {
  parseTrustedThreatRegisterText,
  prioritizePullRequestFiles
} from "../../src/github/content.js";
import { parseConfigText } from "../../src/config/load.js";
import { HedgeContextSchema } from "../../src/domain/schemas.js";
import { bindThreatRegisterState, emptyRegister } from "../../src/register/store.js";

describe("GitHub patch evidence prioritization", () => {
  it("prioritizes attack-surface files over API response order", () => {
    const files = prioritizePullRequestFiles([
      { filename: "README.md" },
      { filename: "docs/architecture.md" },
      { filename: "app/api/admin/route.ts" },
      { filename: "src/auth/session.ts" },
      { filename: "tests/ui.test.ts" }
    ]);
    expect(files.slice(0, 2).map((file) => file.filename)).toEqual([
      "app/api/admin/route.ts",
      "src/auth/session.ts"
    ]);
  });

  it("uses the previous name when a security-relevant file is renamed", () => {
    const files = prioritizePullRequestFiles([
      { filename: "src/moved.ts", previous_filename: "src/auth/policy.ts" },
      { filename: "src/component.ts" }
    ]);
    expect(files[0]?.filename).toBe("src/moved.ts");
  });
});

describe("trusted full-register integrity", () => {
  it("discards lifecycle and IDs when the full register digest is tampered", () => {
    const config = parseConfigText("framework: nextjs\n");
    const context = HedgeContextSchema.parse({});
    const baseSha = "a".repeat(40);
    const register = emptyRegister();
    register.graph = {
      schemaVersion: "0.1",
      generatedAt: new Date(0).toISOString(),
      repository: "example/repository",
      sourceCommit: baseSha,
      framework: "nextjs",
      nodes: [],
      edges: [],
      assumptions: [],
      unknowns: []
    };
    bindThreatRegisterState(register, { sourceCommit: baseSha });

    const valid = parseTrustedThreatRegisterText(JSON.stringify(register), {
      config,
      context,
      baseSha
    });
    expect(valid.register).toBeDefined();

    const tampered = structuredClone(register);
    tampered.nextRiskNumber = 999;
    const invalid = parseTrustedThreatRegisterText(JSON.stringify(tampered), {
      config,
      context,
      baseSha
    });
    expect(invalid.register).toBeUndefined();
    expect(invalid.warnings.join(" ")).toContain("entire register was ignored");
  });
});
