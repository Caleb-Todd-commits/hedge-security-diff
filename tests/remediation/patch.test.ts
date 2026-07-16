import { describe, expect, it } from "vitest";
import {
  createRemediationPatchManifest,
  sanitizeRemediationSummary,
  validateRemediationPatch
} from "../../src/remediation/patch.js";

function patchFor(path: string, body = "+export const repaired = true;\n"): string {
  return [
    `diff --git a/${path} b/${path}`,
    "index 1111111..2222222 100644",
    `--- a/${path}`,
    `+++ b/${path}`,
    "@@ -0,0 +1 @@",
    body
  ].join("\n");
}

describe("remediation patch validation", () => {
  it("returns a digest and normalized file inventory for a regular text patch", () => {
    const result = validateRemediationPatch(patchFor("app/api/items/route.ts"));
    expect(result.digest).toMatch(/^[a-f0-9]{64}$/);
    expect(result.files).toEqual(["app/api/items/route.ts"]);
  });

  it.each([
    ".hedge.yml",
    ".hedge/analysis.json",
    "threatmodel.json",
    "THREATMODEL.md",
    ".git/config",
    ".gitmodules",
    ".github/workflows/hedge.yml",
    "package-lock.json",
    ".next/server/app.js",
    "dist/index.js",
    "coverage/results.json"
  ])("rejects protected path %s", (path) => {
    expect(() => validateRemediationPatch(patchFor(path))).toThrow();
  });

  it("requires explicit approval before a workflow can change", () => {
    expect(
      validateRemediationPatch(patchFor(".github/workflows/ci.yml"), {
        allowWorkflows: true
      }).files
    ).toEqual([".github/workflows/ci.yml"]);
  });

  it("rejects traversal, symlinks, submodules, binary patches, and combined diffs", () => {
    expect(() => validateRemediationPatch(patchFor("../../outside.ts"))).toThrow(/escapes/);
    expect(() =>
      validateRemediationPatch(
        "diff --git a/link b/link\nnew file mode 120000\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+target\n"
      )
    ).toThrow(/regular file mode/);
    expect(() =>
      validateRemediationPatch(
        "diff --git a/vendor b/vendor\nnew file mode 160000\n--- /dev/null\n+++ b/vendor\n@@ -0,0 +1 @@\n+submodule\n"
      )
    ).toThrow(/regular file mode/);
    expect(() =>
      validateRemediationPatch(
        "diff --git a/image.png b/image.png\nGIT binary patch\nliteral 0\nHcmV?d00001\n"
      )
    ).toThrow(/Binary patch/);
    expect(() => validateRemediationPatch("diff --cc route.ts\n")).toThrow();
  });

  it("enforces byte and file-count ceilings", () => {
    expect(() => validateRemediationPatch(patchFor("route.ts"), { maxBytes: 10 })).toThrow(/limit/);
    const twoFiles = `${patchFor("one.ts")}\n${patchFor("two.ts")}`;
    expect(() => validateRemediationPatch(twoFiles, { maxFiles: 1 })).toThrow(/changes 2 files/);
  });

  it("binds a manifest to the exact source revision and risk", () => {
    const manifest = createRemediationPatchManifest(patchFor("route.ts"), {
      riskId: "HEDGE-123",
      sourceCommit: "a".repeat(40)
    });
    expect(manifest).toMatchObject({
      schemaVersion: "0.1",
      riskId: "HEDGE-123",
      sourceCommit: "a".repeat(40),
      files: ["route.ts"]
    });
  });

  it("bounds model prose, prevents mentions, and neutralizes hidden comments", () => {
    const sanitized = sanitizeRemediationSummary(
      `@maintainer\n<!-- hidden -->\n${"x".repeat(5000)}`
    );
    expect(sanitized).not.toContain("@maintainer");
    expect(sanitized).not.toContain("<!--");
    expect(sanitized).not.toContain("<script>");
    expect(sanitizeRemediationSummary("<script>alert(1)</script>")).toContain("&lt;script&gt;");
    expect(sanitized.length).toBeLessThanOrEqual(4000);
    expect(sanitized).toContain("[summary truncated]");
  });
});
