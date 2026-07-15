import { mkdtemp, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { writeJsonFile, writeTextFile } from "../../src/utils/fs.js";

describe("atomic file writes", () => {
  it("leaves a complete JSON document under concurrent replacement", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-atomic-"));
    const path = join(root, "state.json");
    await Promise.all(
      Array.from({ length: 20 }, (_, index) =>
        writeJsonFile(path, { index, payload: "x".repeat(1000) })
      )
    );
    const parsed = JSON.parse(await readFile(path, "utf8")) as {
      index: number;
      payload: string;
    };
    expect(parsed.index).toBeGreaterThanOrEqual(0);
    expect(parsed.index).toBeLessThan(20);
    expect(parsed.payload).toHaveLength(1000);
    expect((await readdir(root)).some((name) => name.endsWith(".tmp"))).toBe(false);
  });

  it("normalizes text files to one trailing newline", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-text-"));
    const path = join(root, "report.md");
    await writeTextFile(path, "hello");
    expect(await readFile(path, "utf8")).toBe("hello\n");
  });
});
