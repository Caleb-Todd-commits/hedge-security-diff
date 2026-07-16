import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { parseConfigText } from "../../src/config/load.js";
import { checkHedge } from "../../src/core/run.js";
import { emptyRegister } from "../../src/register/store.js";

const execFileAsync = promisify(execFile);

describe("exact base/head analysis", () => {
  it("ignores stale stored graph state and working-tree bytes", async () => {
    const root = await createRepository();
    const route = join(root, "app/api/items/route.ts");
    await mkdir(join(root, "app/api/items"), { recursive: true });
    await writeFile(
      join(root, "package.json"),
      JSON.stringify({ dependencies: { next: "15.0.0" } })
    );
    await writeFile(route, "export function GET() { return Response.json({ ok: true }); }\n");
    const base = await commitAll(root, "base");

    await writeFile(
      route,
      "export async function POST() { await prisma.item.create({ data: {} }); return Response.json({ ok: true }); }\n"
    );
    const head = await commitAll(root, "head");
    await writeFile(route, "malformed uncommitted working tree {{{\n");

    const config = parseConfigText("framework: nextjs\n");
    const stale = emptyRegister();
    stale.graph = {
      schemaVersion: "0.1",
      generatedAt: new Date(0).toISOString(),
      repository: "example/repository",
      framework: "nextjs",
      nodes: [],
      edges: [],
      assumptions: [],
      unknowns: []
    };

    const withStaleState = await checkHedge({
      root,
      config,
      repository: "example/repository",
      baseRevision: base,
      headRevision: head,
      baselineRegister: stale
    });
    const fresh = await checkHedge({
      root,
      config,
      repository: "example/repository",
      baseRevision: base,
      headRevision: head,
      baselineRegister: emptyRegister()
    });

    expect(withStaleState.delta).toEqual(fresh.delta);
    expect(withStaleState.surfaceChanged).toBe(true);
    expect(withStaleState.baseCommit).toBe(base);
    expect(withStaleState.headCommit).toBe(head);
    expect(withStaleState.graph.nodes.some((node) => node.label === "POST /api/items")).toBe(true);
    expect(
      withStaleState.graph.nodes
        .flatMap((node) => node.evidence)
        .every((item) => item.commit === head)
    ).toBe(true);
  });

  it("confirms no delta only for exact revisions with complete supported coverage", async () => {
    const root = await createRepository();
    await mkdir(join(root, "app/api/health"), { recursive: true });
    await writeFile(
      join(root, "package.json"),
      JSON.stringify({ dependencies: { next: "15.0.0" } })
    );
    await writeFile(
      join(root, "app/api/health/route.ts"),
      "export function GET() { return Response.json({ ok: true }); }\n"
    );
    const revision = await commitAll(root, "healthy");

    const result = await checkHedge({
      root,
      config: parseConfigText("framework: nextjs\n"),
      baseRevision: revision,
      headRevision: revision
    });

    expect(result.surfaceChanged).toBe(false);
    expect(result.analysis.confirmedNoDelta).toBe(true);
    expect(result.analysis.coverage?.status).toBe("complete");
    expect(result.analysis.analysisHealth?.status).toBe("complete");
    expect(result.analysis.model).toBe("none");
    expect(result.report).toContain("Confirmed no-delta: **yes**");
  });

  it("records deleted architecture surfaces from the exact head", async () => {
    const root = await createRepository();
    const route = join(root, "app/api/legacy/route.ts");
    await mkdir(join(root, "app/api/legacy"), { recursive: true });
    await writeFile(
      join(root, "package.json"),
      JSON.stringify({ dependencies: { next: "15.0.0" } })
    );
    await writeFile(route, "export function GET() { return Response.json({ ok: true }); }\n");
    const base = await commitAll(root, "route");
    await rm(route);
    const head = await commitAll(root, "delete route");

    const result = await checkHedge({
      root,
      config: parseConfigText("framework: nextjs\n"),
      baseRevision: base,
      headRevision: head
    });
    expect(result.delta.removedNodes.some((node) => node.label === "GET /api/legacy")).toBe(true);
  });

  it("persists one graph bound to the resolved exact head commit", async () => {
    const root = await createRepository();
    const route = join(root, "app/api/items/route.ts");
    await mkdir(join(root, "app/api/items"), { recursive: true });
    await writeFile(
      join(root, "package.json"),
      JSON.stringify({ dependencies: { next: "15.0.0" } })
    );
    await writeFile(route, "export function GET() { return Response.json({ ok: true }); }\n");
    const base = await commitAll(root, "base");
    await writeFile(
      route,
      "export async function POST() { await prisma.item.create({ data: {} }); return Response.json({ ok: true }); }\n"
    );
    const head = await commitAll(root, "head");

    const result = await checkHedge({
      root,
      config: parseConfigText("framework: nextjs\n"),
      baseRevision: base,
      headRevision: head,
      sourceCommit: "not-the-resolved-head",
      persist: true
    });
    const graph = JSON.parse(await readFile(join(root, ".hedge", "graph.json"), "utf8"));
    const register = JSON.parse(await readFile(join(root, "threatmodel.json"), "utf8"));

    expect(graph).toEqual(result.graph);
    expect(register.graph).toEqual(result.graph);
    expect(register.stateIntegrity.sourceCommit).toBe(head);
    expect(register.runs.at(-1)?.sourceCommit).toBe(head);
  });

  it("can collect without writing reports through a target-controlled .hedge symlink", async () => {
    const root = await createRepository();
    const route = join(root, "app/api/items/route.ts");
    await mkdir(join(root, "app/api/items"), { recursive: true });
    await writeFile(
      join(root, "package.json"),
      JSON.stringify({ dependencies: { next: "15.0.0" } })
    );
    await writeFile(route, "export function GET() { return Response.json({ ok: true }); }\n");
    const base = await commitAll(root, "base");
    await writeFile(
      route,
      "export async function POST() { return Response.json({ ok: true }); }\n"
    );
    const head = await commitAll(root, "head");
    const outside = await mkdtemp(join(tmpdir(), "hedge-collect-outside-"));
    await symlink(outside, join(root, ".hedge"));

    const result = await checkHedge({
      root,
      config: parseConfigText("framework: nextjs\n"),
      baseRevision: base,
      headRevision: head,
      writeArtifacts: false
    });

    expect(result.surfaceChanged).toBe(true);
    expect(result.report).toContain("Hedge security architecture diff");
    expect(await readdir(outside)).toEqual([]);
  });
});

async function createRepository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "hedge-exact-core-"));
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
  return execFileAsync("git", args, { cwd: root, encoding: "utf8", maxBuffer: 2_000_000 });
}
