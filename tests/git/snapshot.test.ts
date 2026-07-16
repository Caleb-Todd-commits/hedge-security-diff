import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { parseConfigText } from "../../src/config/load.js";
import {
  GitSnapshotError,
  collectGitSourceFileInventory,
  parseGitTreeOutput,
  resolveGitCommit
} from "../../src/git/snapshot.js";

const execFileAsync = promisify(execFile);

describe("exact Git snapshot collection", () => {
  it("reads canonical base and head commits without using the working-tree revision", async () => {
    const root = await createRepository();
    const route = join(root, "app", "api", "files", "route.ts");
    await mkdir(join(root, "app", "api", "files"), { recursive: true });
    await writeFile(route, "export function GET() { return Response.json({ base: true }); }\n");
    const base = await commitAll(root, "base");

    await writeFile(
      route,
      "export async function POST() { await prisma.file.create({ data: {} }); }\n"
    );
    const head = await commitAll(root, "head");

    const config = parseConfigText("framework: nextjs\n");
    const baseSnapshot = await collectGitSourceFileInventory({
      root,
      revision: base.slice(0, 12),
      config
    });
    const headSnapshot = await collectGitSourceFileInventory({ root, revision: head, config });

    expect(baseSnapshot.commit).toBe(base);
    expect(headSnapshot.commit).toBe(head);
    expect(baseSnapshot.inventory.files[0]?.content).toContain("base: true");
    expect(baseSnapshot.inventory.files[0]?.content).not.toContain("prisma.file.create");
    expect(headSnapshot.inventory.files[0]?.content).toContain("prisma.file.create");
    expect(baseSnapshot.inventory.files[0]?.commit).toBe(base);
    expect(headSnapshot.inventory.files[0]?.commit).toBe(head);
  });

  it("applies trusted ignore and source budgets before reading blobs", async () => {
    const root = await createRepository();
    for (const name of ["one", "two", "ignored"]) {
      const directory = join(root, "app", "api", name);
      await mkdir(directory, { recursive: true });
      await writeFile(
        join(directory, "route.ts"),
        `export function GET() { return Response.json({ route: "${name}" }); }\n`
      );
    }
    const commit = await commitAll(root, "routes");
    const config = parseConfigText(`
framework: nextjs
ignored_paths:
  - app/api/ignored/**
limits:
  max_files: 1
  max_bytes: 10000
`);

    const snapshot = await collectGitSourceFileInventory({ root, revision: commit, config });
    expect(snapshot.inventory.files).toHaveLength(1);
    expect(snapshot.inventory.files[0]?.path).toBe("app/api/one/route.ts");
    expect(snapshot.inventory.stats).toMatchObject({
      discoveredFiles: 2,
      includedFiles: 1,
      omittedByFileLimit: 1,
      omittedByByteLimit: 0
    });

    config.limits.max_files = 10;
    config.limits.max_bytes = 1;
    const byteBounded = await collectGitSourceFileInventory({ root, revision: commit, config });
    expect(byteBounded.inventory.files).toHaveLength(0);
    expect(byteBounded.inventory.stats.omittedByByteLimit).toBe(2);
  });

  it("rejects tracked symlinks instead of following content outside the repository", async () => {
    const root = await createRepository();
    const outside = await mkdtemp(join(tmpdir(), "hedge-git-outside-"));
    await writeFile(join(outside, "secret.ts"), "must-not-be-read\n");
    await mkdir(join(root, "app", "api", "safe"), { recursive: true });
    await mkdir(join(root, "app", "api", "leaked"), { recursive: true });
    await writeFile(
      join(root, "app", "api", "safe", "route.ts"),
      "export function GET() { return Response.json({ ok: true }); }\n"
    );
    await symlink(join(outside, "secret.ts"), join(root, "app", "api", "leaked", "route.ts"));
    const commit = await commitAll(root, "symlink");

    const snapshot = await collectGitSourceFileInventory({
      root,
      revision: commit,
      config: parseConfigText(undefined)
    });
    expect(snapshot.inventory.files.map((file) => file.path)).toEqual(["app/api/safe/route.ts"]);
    expect(snapshot.inventory.files.some((file) => file.content.includes("must-not-be-read"))).toBe(
      false
    );
    expect(snapshot.inventory.stats.omittedUnsafeOrUnreadable).toBe(1);
  });

  it("does not invoke checkout smudge filters while reading source blobs", async () => {
    const root = await createRepository();
    const marker = join(root, "smudge-ran");
    await mkdir(join(root, "app", "api", "safe"), { recursive: true });
    await writeFile(join(root, ".gitattributes"), "*.ts filter=hedge-test-smudge\n");
    await writeFile(
      join(root, "app", "api", "safe", "route.ts"),
      "export function GET() { return Response.json({ ok: true }); }\n"
    );
    const commit = await commitAll(root, "filtered source");
    await git(root, ["config", "filter.hedge-test-smudge.smudge", `touch ${marker}`]);
    await git(root, ["config", "filter.hedge-test-smudge.required", "true"]);

    const snapshot = await collectGitSourceFileInventory({
      root,
      revision: commit,
      config: parseConfigText(undefined)
    });
    expect(snapshot.inventory.files[0]?.content).toContain("Response.json");
    await expect(readFile(marker, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("records invalid UTF-8 source as omitted instead of analyzing replacement text", async () => {
    const root = await createRepository();
    await mkdir(join(root, "app", "api", "invalid"), { recursive: true });
    await writeFile(join(root, "package.json"), '{"dependencies":{"next":"15.0.0"}}\n');
    await writeFile(
      join(root, "app", "api", "invalid", "route.ts"),
      Buffer.from([0x65, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x20, 0xff, 0xfe])
    );
    const commit = await commitAll(root, "invalid encoding");

    const snapshot = await collectGitSourceFileInventory({
      root,
      revision: commit,
      config: parseConfigText("framework: nextjs\n")
    });
    expect(snapshot.inventory.files.map((file) => file.path)).toEqual(["package.json"]);
    expect(snapshot.inventory.stats.omittedBinary).toBe(1);
  });

  it("rejects option-like revisions and bounds tree enumeration", async () => {
    const root = await createRepository();
    await writeFile(join(root, "route.ts"), "export function GET() {}\n");
    await writeFile(join(root, "package.json"), '{"name":"snapshot-limit"}\n');
    const commit = await commitAll(root, "route");

    await expect(resolveGitCommit(root, "--help")).rejects.toMatchObject({
      code: "invalid-revision"
    });
    await expect(
      collectGitSourceFileInventory({
        root,
        revision: commit,
        config: parseConfigText(undefined),
        maxTreeEntries: 1
      })
    ).rejects.toMatchObject({ code: "tree-entry-limit" });
    await expect(
      collectGitSourceFileInventory({
        root,
        revision: commit,
        config: parseConfigText(undefined),
        maxTreeOutputBytes: 1
      })
    ).rejects.toMatchObject({ code: "tree-output-limit" });
  });

  it("does not let inherited Git environment variables redirect object reads", async () => {
    const root = await createRepository();
    await writeFile(join(root, "package.json"), '{"name":"isolated-git-env"}\n');
    const commit = await commitAll(root, "isolated environment");
    const previous = process.env.GIT_DIR;
    process.env.GIT_DIR = join(root, "does-not-exist");
    try {
      const snapshot = await collectGitSourceFileInventory({
        root,
        revision: commit,
        config: parseConfigText(undefined)
      });
      expect(snapshot.commit).toBe(commit);
    } finally {
      if (previous === undefined) delete process.env.GIT_DIR;
      else process.env.GIT_DIR = previous;
    }
  });
});

describe("Git tree parser", () => {
  it("drops traversal, control-character, and .git paths", () => {
    const objectId = "a".repeat(40);
    const parsed = parseGitTreeOutput(
      [
        `100644 blob ${objectId} 1\tapp/api/ok/route.ts`,
        `100644 blob ${objectId} 1\t../escape.ts`,
        `100644 blob ${objectId} 1\t.git/config.json`,
        `100644 blob ${objectId} 1\tapp/api/bad\nroute.ts`,
        ""
      ].join("\0"),
      10
    );
    expect(parsed.entries.map((entry) => entry.path)).toEqual(["app/api/ok/route.ts"]);
    expect(parsed.rejectedUnsafePaths).toBe(3);
  });

  it("fails closed on malformed tree records", () => {
    expect(() => parseGitTreeOutput("not-a-tree-record\0", 10)).toThrow(GitSnapshotError);
  });
});

async function createRepository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "hedge-git-snapshot-"));
  await git(root, ["init", "--quiet"]);
  await git(root, ["config", "user.email", "hedge-tests@example.invalid"]);
  await git(root, ["config", "user.name", "Hedge Tests"]);
  return root;
}

async function commitAll(root: string, message: string): Promise<string> {
  await git(root, ["add", "--all"]);
  await git(root, ["commit", "--quiet", "-m", message]);
  const { stdout } = await git(root, ["rev-parse", "HEAD"]);
  return stdout.trim().toLowerCase();
}

async function git(root: string, args: string[]): Promise<{ stdout: string; stderr: string }> {
  return execFileAsync("git", args, {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 2_000_000
  });
}
