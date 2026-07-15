import { describe, expect, it } from "vitest";
import { prioritizePullRequestFiles } from "../../src/github/content.js";

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
