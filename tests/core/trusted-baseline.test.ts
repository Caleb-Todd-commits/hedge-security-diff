import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseConfigText } from "../../src/config/load.js";
import { checkHedge, initializeHedge } from "../../src/core/run.js";
import { emptyRegister } from "../../src/register/store.js";

describe("trusted baseline isolation", () => {
  it("uses an explicit empty base register instead of local PR-head state", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-baseline-"));
    const routeDirectory = join(root, "app", "api", "files");
    await mkdir(routeDirectory, { recursive: true });
    await writeFile(
      join(routeDirectory, "route.ts"),
      `export async function POST(request: Request) {
        const body = await request.formData();
        await prisma.file.create({ data: { name: String(body.get("name")) } });
        return Response.json({ ok: true });
      }
`
    );

    const config = parseConfigText("framework: nextjs\n");
    await initializeHedge(root, config, "example/repository");

    const localStateResult = await checkHedge({
      root,
      config,
      repository: "example/repository"
    });
    expect(localStateResult.surfaceChanged).toBe(false);

    const trustedEmptyResult = await checkHedge({
      root,
      config,
      repository: "example/repository",
      baselineRegister: emptyRegister()
    });
    expect(trustedEmptyResult.surfaceChanged).toBe(true);
    expect(trustedEmptyResult.findings.length).toBeGreaterThan(0);
  });
});
