import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  collectSourceFileInventory,
  collectSourceFiles,
  relevanceScore
} from "../../src/analyzers/files.js";
import { parseConfigText } from "../../src/config/load.js";

describe("bounded repository source collection", () => {
  it("prioritizes supported entry points over documentation", () => {
    expect(relevanceScore("app/api/files/route.ts")).toBeGreaterThan(
      relevanceScore("docs/route.ts")
    );
  });

  it("refuses symbolic links that could escape the repository", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-files-"));
    const outside = await mkdtemp(join(tmpdir(), "hedge-outside-"));
    await mkdir(join(root, "app", "api", "safe"), { recursive: true });
    await writeFile(
      join(root, "app", "api", "safe", "route.ts"),
      "export function GET() { return Response.json({ ok: true }); }\n"
    );
    await writeFile(join(outside, "secret.json"), '{"secret":"must-not-be-read"}\n');
    await symlink(join(outside, "secret.json"), join(root, "leaked.json"));

    const files = await collectSourceFiles(root, parseConfigText(undefined));
    expect(files.map((file) => file.path)).toContain("app/api/safe/route.ts");
    expect(files.map((file) => file.path)).not.toContain("leaked.json");
    expect(files.some((file) => file.content.includes("must-not-be-read"))).toBe(false);
  });

  it("skips binary-looking files even when their extension is supported", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-binary-"));
    await writeFile(join(root, "malformed.json"), Buffer.from([0x7b, 0x00, 0x7d]));
    const files = await collectSourceFiles(root, parseConfigText(undefined));
    expect(files).toHaveLength(0);
  });

  it("reports explicit coverage loss when repository budgets omit files", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-budget-"));
    await mkdir(join(root, "app", "api", "one"), { recursive: true });
    await mkdir(join(root, "app", "api", "two"), { recursive: true });
    await writeFile(join(root, "app", "api", "one", "route.ts"), "export function GET() {}\n");
    await writeFile(join(root, "app", "api", "two", "route.ts"), "export function POST() {}\n");
    const config = parseConfigText(undefined);
    config.limits.max_files = 1;
    const inventory = await collectSourceFileInventory(root, config);
    expect(inventory.files).toHaveLength(1);
    expect(inventory.stats.discoveredFiles).toBe(2);
    expect(inventory.stats.omittedByFileLimit).toBe(1);
  });
});
