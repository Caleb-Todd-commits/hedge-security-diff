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
});
