import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildAttackSurfaceGraph } from "../../src/analyzers/build-graph.js";
import { parseConfigText } from "../../src/config/load.js";
import { diffGraphs, hasSecurityArchitectureDelta } from "../../src/graph/diff.js";

async function writeRoute(root: string, content: string): Promise<void> {
  const directory = join(root, "app", "api", "items");
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, "route.ts"), content);
}

describe("semantic graph identity", () => {
  it("does not report architecture churn when code only moves lines", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-stable-"));
    const config = parseConfigText("framework: nextjs\n");
    await writeRoute(
      root,
      `export async function POST(request: Request) {
         await requireAuth();
         await prisma.item.create({ data: await request.json() });
         return Response.json({ ok: true });
       }\n`
    );
    const before = await buildAttackSurfaceGraph({ root, config });
    await writeRoute(
      root,
      `// documentation-only line movement

       export async function POST(request: Request) {
         await requireAuth();

         await prisma.item.create({ data: await request.json() });
         return Response.json({ ok: true });
       }\n`
    );
    const after = await buildAttackSurfaceGraph({ root, config });
    expect(hasSecurityArchitectureDelta(diffGraphs(before, after))).toBe(false);
  });

  it("reports security metadata changes on a stable operation identity", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-metadata-"));
    const config = parseConfigText("framework: nextjs\n");
    await writeRoute(
      root,
      `export async function GET() {
         await fetch("https://api.example.test/data");
         return Response.json({ ok: true });
       }\n`
    );
    const before = await buildAttackSurfaceGraph({ root, config });
    await writeRoute(
      root,
      `export async function GET(request: Request) {
         const target = new URL(request.url).searchParams.get("target");
         await fetch(target!);
         return Response.json({ ok: true });
       }\n`
    );
    const after = await buildAttackSurfaceGraph({ root, config });
    const delta = diffGraphs(before, after);
    expect(delta.changedNodes.some((pair) => pair.after.kind === "external-service")).toBe(true);
  });

  it("applies evidence from matching Next.js middleware without protecting unrelated routes", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-next-middleware-"));
    const config = parseConfigText("framework: nextjs\n");
    await mkdir(join(root, "app", "api", "private"), { recursive: true });
    await mkdir(join(root, "app", "public"), { recursive: true });
    await writeFile(
      join(root, "middleware.ts"),
      `export default auth((request: Request) => NextResponse.next());
       export const config = { matcher: "/api/:path*" };`
    );
    await writeFile(
      join(root, "app", "api", "private", "route.ts"),
      `export async function GET(){ return Response.json({ ok: true }); }`
    );
    await mkdir(join(root, "app", "public", "route"), { recursive: true });
    await writeFile(
      join(root, "app", "public", "route", "route.ts"),
      `export async function GET(){ return Response.json({ ok: true }); }`
    );
    const graph = await buildAttackSurfaceGraph({ root, config });
    const privateRoute = graph.nodes.find((node) => node.label === "GET /api/private");
    const publicRoute = graph.nodes.find((node) => node.label === "GET /public/route");
    expect(privateRoute?.controls.some((control) => control.type === "authentication")).toBe(true);
    expect(
      privateRoute?.controls.find((control) => control.type === "authentication")?.evidence[0]?.file
    ).toBe("middleware.ts");
    expect(publicRoute?.controls.some((control) => control.type === "authentication")).toBe(false);
  });

  it("does not claim protection from a dynamic Next.js middleware matcher", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-next-dynamic-matcher-"));
    const config = parseConfigText("framework: nextjs\n");
    await mkdir(join(root, "app", "api", "private"), { recursive: true });
    await writeFile(
      join(root, "middleware.ts"),
      `export default auth((request: Request) => NextResponse.next());
       const matcher = process.env.MIDDLEWARE_MATCHER;
       export const config = { matcher };`
    );
    await writeFile(
      join(root, "app", "api", "private", "route.ts"),
      `export async function GET(){ return Response.json({ ok: true }); }`
    );

    const graph = await buildAttackSurfaceGraph({ root, config });
    const route = graph.nodes.find((node) => node.label === "GET /api/private");
    expect(route?.controls.some((control) => control.type === "authentication")).toBe(false);
    expect(graph.coverage?.status).toBe("partial");
    expect(graph.coverage?.diagnostics).toContainEqual(
      expect.objectContaining({ code: "unsupported-dynamic-matcher", file: "middleware.ts" })
    );
  });

  it("marks unresolved control helpers as inferred and coverage as partial", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-unresolved-helper-"));
    const config = parseConfigText("framework: nextjs\n");
    await writeRoute(
      root,
      `import { requireAuth } from "@/auth";
       export async function POST() {
         await requireAuth();
         return Response.json({ ok: true });
       }`
    );

    const graph = await buildAttackSurfaceGraph({ root, config });
    const route = graph.nodes.find((node) => node.label === "POST /api/items");
    expect(route?.controls.find((control) => control.type === "authentication")?.assurance).toBe(
      "inferred"
    );
    expect(graph.coverage?.status).toBe("partial");
    expect(graph.coverage?.diagnostics).toContainEqual(
      expect.objectContaining({ code: "unresolved-control-helper" })
    );
  });

  it("records malformed TypeScript as parser coverage loss", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-parser-loss-"));
    const config = parseConfigText("framework: nextjs\n");
    await writeRoute(root, `export async function POST( { return Response.json({ ok: true });`);
    const graph = await buildAttackSurfaceGraph({ root, config });
    expect(graph.coverage?.status).toBe("partial");
    expect(graph.coverage?.diagnostics).toContainEqual(
      expect.objectContaining({ code: "typescript-parser-diagnostic" })
    );
  });

  it("records unresolved imported route handlers as partial coverage", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-imported-handler-"));
    const config = parseConfigText("framework: nextjs\n");
    await writeRoute(
      root,
      `import { handler } from "./handler";
       export { handler as POST };`
    );
    const graph = await buildAttackSurfaceGraph({ root, config });
    expect(graph.coverage?.status).toBe("partial");
    expect(graph.coverage?.diagnostics).toContainEqual(
      expect.objectContaining({ code: "unresolved-imported-route-handler" })
    );
  });

  it("auto-detects Next.js from Pages API routes", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-pages-auto-"));
    const config = parseConfigText("framework: auto\n");
    await mkdir(join(root, "pages", "api"), { recursive: true });
    await writeFile(
      join(root, "pages", "api", "legacy.ts"),
      `export default function handler(_req: any, res: any) {
         res.status(200).json({ ok: true });
       }`
    );

    const graph = await buildAttackSurfaceGraph({ root, config });
    expect(graph.framework).toBe("nextjs");
    expect(graph.nodes.some((node) => node.label === "ANY /api/legacy")).toBe(true);
  });
});
