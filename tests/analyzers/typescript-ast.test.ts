import { describe, expect, it } from "vitest";
import {
  extractTypeScriptFacts,
  nextMiddlewareMatchesPath
} from "../../src/analyzers/typescript-ast.js";

function source(path: string, content: string) {
  return { path, absolutePath: `/tmp/${path}`, content, bytes: Buffer.byteLength(content) };
}

describe("TypeScript AST extraction", () => {
  it("scopes controls to the route handler rather than unrelated helpers", () => {
    const facts = extractTypeScriptFacts(
      source(
        "app/api/items/route.ts",
        `async function helper() { return auth(); }
         export async function POST(request: Request) {
           await prisma.item.create({ data: await request.json() });
           return Response.json({ ok: true });
         }`
      ),
      "nextjs"
    );
    expect(facts.entrypoints).toHaveLength(1);
    expect(
      facts.entrypoints[0]?.controls.some((control) => control.type === "authentication")
    ).toBe(false);
  });

  it("extracts a protected Next.js route and its database operation", () => {
    const facts = extractTypeScriptFacts(
      source(
        "app/api/items/[id]/route.ts",
        `export async function PATCH(request: Request) {
          const session = await auth();
          const userId = session.user.id;
          await prisma.item.update({ where: { id: "1", userId }, data: {} });
          return Response.json({ ok: true });
        }`
      ),
      "nextjs"
    );
    const route = facts.entrypoints[0]!;
    expect(route.path).toBe("/api/items/:id");
    expect(route.controls.map((control) => control.type)).toEqual(
      expect.arrayContaining(["authentication", "ownership"])
    );
    expect(route.operations.some((operation) => operation.kind === "database")).toBe(true);
  });

  it("resolves an exported alias as an HTTP handler", () => {
    const facts = extractTypeScriptFacts(
      source(
        "app/api/alias/route.ts",
        `async function handler() { return Response.json({ ok: true }); }
         export { handler as GET };`
      ),
      "nextjs"
    );
    expect(facts.entrypoints.map((entry) => `${entry.method} ${entry.path}`)).toContain(
      "GET /api/alias"
    );
  });

  it("resolves Express named handlers", () => {
    const facts = extractTypeScriptFacts(
      source(
        "src/app.ts",
        `async function create(req: any, res: any) { await requireAuth(req); res.end(); }
         router.post('/items', create);`
      ),
      "express"
    );
    expect(facts.entrypoints[0]?.framework).toBe("express");
    expect(
      facts.entrypoints[0]?.controls.some((control) => control.type === "authentication")
    ).toBe(true);
  });

  it("distinguishes non-secret configuration from credential-like environment variables", () => {
    const facts = extractTypeScriptFacts(
      source(
        "app/api/config/route.ts",
        `export function GET() {
          return Response.json({ bucket: process.env.UPLOAD_BUCKET, token: process.env.API_TOKEN });
        }`
      ),
      "nextjs"
    );
    expect(facts.allSecrets.map((secret) => secret.name)).toEqual(
      expect.arrayContaining(["UPLOAD_BUCKET", "API_TOKEN"])
    );
  });
});

it("follows same-file helper calls used by the handler", () => {
  const facts = extractTypeScriptFacts(
    source(
      "app/api/private/route.ts",
      `async function enforceUser() { return requireAuth(); }
         export async function POST(request: Request) {
           await enforceUser();
           return Response.json({ ok: true });
         }`
    ),
    "nextjs"
  );
  expect(facts.entrypoints[0]?.controls.map((control) => control.type)).toContain("authentication");
});

it("recognizes Next.js authentication wrappers", () => {
  const facts = extractTypeScriptFacts(
    source(
      "app/api/wrapped/route.ts",
      `async function handler(request: Request) { return Response.json({ ok: true }); }
         export const POST = withAuth(handler);`
    ),
    "nextjs"
  );
  expect(facts.entrypoints[0]?.controls.map((control) => control.type)).toContain("authentication");
});

it("combines Express global and route middleware controls", () => {
  const facts = extractTypeScriptFacts(
    source(
      "src/app.ts",
      `function authenticate(req: any, res: any, next: any) { requireAuth(req); next(); }
         function authorizeAdmin(req: any, res: any, next: any) { requireRole(req, "admin"); next(); }
         async function create(req: any, res: any) { await db.item.create({ data: req.body }); res.end(); }
         app.use(authenticate);
         app.post('/admin/items', authorizeAdmin, create);`
    ),
    "express"
  );
  const controls = facts.entrypoints[0]?.controls.map((control) => control.type) ?? [];
  expect(controls).toEqual(expect.arrayContaining(["authentication", "authorization"]));
});

it("distinguishes a fixed outbound host from a request-controlled host", () => {
  const facts = extractTypeScriptFacts(
    source(
      "app/api/proxy/route.ts",
      `export async function GET(request: Request) {
           const city = new URL(request.url).searchParams.get("city");
           await fetch(\`https://weather.example.test?q=\${city}\`);
           const target = new URL(request.url).searchParams.get("target");
           await fetch(target!);
           return Response.json({ ok: true });
         }`
    ),
    "nextjs"
  );
  const outbound =
    facts.entrypoints[0]?.operations.filter((operation) => operation.kind === "external-service") ??
    [];
  expect(outbound[0]?.metadata.userControlledHost).toBe(false);
  expect(outbound[1]?.metadata.userControlledHost).toBe(true);
});

it("tracks a secret alias into a logging sink", () => {
  const facts = extractTypeScriptFacts(
    source(
      "app/api/debug/route.ts",
      `export function GET() {
           const token = process.env.PAYMENT_API_KEY;
           console.log("configured", token);
           return Response.json({ ok: true });
         }`
    ),
    "nextjs"
  );
  const log = facts.entrypoints[0]?.operations.find(
    (operation) => operation.metadata.logging === true
  );
  expect(log?.metadata.secretReferenced).toBe(true);
});

it("applies Express middleware only to matching later routes", () => {
  const facts = extractTypeScriptFacts(
    source(
      "src/app.ts",
      `function requireApiAuth(req: any, res: any, next: any) { requireAuth(req); next(); }
       app.get('/public', (_req: any, res: any) => res.end());
       app.use('/api', requireApiAuth);
       app.get('/api/items', (_req: any, res: any) => res.end());
       app.get('/outside', (_req: any, res: any) => res.end());`
    ),
    "express"
  );
  const byPath = new Map(facts.entrypoints.map((entry) => [entry.path, entry]));
  expect(byPath.get("/public")?.controls.some((control) => control.type === "authentication")).toBe(
    false
  );
  expect(
    byPath.get("/api/items")?.controls.some((control) => control.type === "authentication")
  ).toBe(true);
  expect(
    byPath.get("/outside")?.controls.some((control) => control.type === "authentication")
  ).toBe(false);
});

it("recognizes Express route chains", () => {
  const facts = extractTypeScriptFacts(
    source(
      "src/router.ts",
      `function requireUser(req: any, res: any, next: any) { requireAuth(req); next(); }
       router.route('/items/:id').patch(requireUser, async (req: any, res: any) => {
         await db.item.update({ where: { id: req.params.id }, data: req.body });
         res.end();
       });`
    ),
    "express"
  );
  expect(facts.entrypoints).toHaveLength(1);
  expect(facts.entrypoints[0]?.path).toBe("/items/:id");
  expect(facts.entrypoints[0]?.method).toBe("PATCH");
  expect(facts.entrypoints[0]?.controls.map((control) => control.type)).toContain("authentication");
  expect(facts.entrypoints[0]?.operations).toHaveLength(1);
  expect(facts.entrypoints[0]?.operations[0]?.metadata.userControlled).toBe(true);
});

it("propagates request influence through helper arguments and destructuring", () => {
  const facts = extractTypeScriptFacts(
    source(
      "app/api/proxy/route.ts",
      `async function requestRemote(target: string) { await fetch(target); }
       export async function POST(request: Request) {
         const { target } = await request.json();
         await requestRemote(target);
         return Response.json({ ok: true });
       }`
    ),
    "nextjs"
  );
  const outbound = facts.entrypoints[0]?.operations.find(
    (operation) => operation.kind === "external-service"
  );
  expect(outbound?.metadata.userControlledHost).toBe(true);
});

it("propagates secret aliases through helper arguments", () => {
  const facts = extractTypeScriptFacts(
    source(
      "app/api/debug/route.ts",
      `function debug(value: string) { console.log(value); }
       export function GET() {
         const { PAYMENT_API_KEY: paymentKey } = process.env;
         debug(paymentKey);
         return Response.json({ ok: true });
       }`
    ),
    "nextjs"
  );
  const log = facts.entrypoints[0]?.operations.find(
    (operation) => operation.metadata.logging === true
  );
  expect(log?.metadata.secretReferenced).toBe(true);
  expect(facts.allSecrets.map((secret) => secret.name)).toContain("PAYMENT_API_KEY");
});

it("extracts module-level Next.js Server Actions as entry points", () => {
  const facts = extractTypeScriptFacts(
    source(
      "app/actions/account.ts",
      `"use server";
       export async function updateAccount(input: { name: string }) {
         await prisma.account.update({ where: { id: input.name }, data: input });
       }`
    ),
    "nextjs"
  );
  const action = facts.entrypoints.find((entry) => entry.method === "ACTION");
  expect(action?.path).toBe("/server-action/updateAccount");
  expect(action?.operations.some((operation) => operation.kind === "database")).toBe(true);
  expect(action?.operations[0]?.metadata.userControlled).toBe(true);
});

it("extracts function-level Server Actions without treating ordinary exports as actions", () => {
  const facts = extractTypeScriptFacts(
    source(
      "app/actions/mixed.ts",
      `export async function ordinary() { return "not an action"; }
       export async function removeItem(id: string) {
         "use server";
         await prisma.item.delete({ where: { id } });
       }`
    ),
    "nextjs"
  );
  expect(facts.entrypoints.map((entry) => entry.handlerName)).toEqual(["removeItem"]);
});

it("extracts Next.js middleware controls and static matchers", () => {
  const facts = extractTypeScriptFacts(
    source(
      "middleware.ts",
      `export default auth((request: Request) => NextResponse.next());
         export const config = { matcher: ["/api/:path*", "/dashboard/:path*"] };`
    ),
    "nextjs"
  );
  expect(facts.middlewareRules).toHaveLength(1);
  expect(facts.middlewareRules[0]?.matchers).toEqual(["/api/:path*", "/dashboard/:path*"]);
  expect(
    facts.middlewareRules[0]?.controls.some((control) => control.type === "authentication")
  ).toBe(true);
  expect(facts.middlewareRules[0]?.controls[0]?.sourcePath).toBe("middleware.ts");
});

it("matches supported Next.js middleware path patterns conservatively", () => {
  expect(nextMiddlewareMatchesPath(["/api/:path*"], "/api/items")).toBe(true);
  expect(nextMiddlewareMatchesPath(["/api/:path*"], "/api")).toBe(true);
  expect(nextMiddlewareMatchesPath(["/users/:id"], "/users/123")).toBe(true);
  expect(nextMiddlewareMatchesPath(["/users/:id"], "/users/123/settings")).toBe(false);
  expect(nextMiddlewareMatchesPath(["/((?!public).*)"], "/api/items")).toBe(false);
});

it("detects custom-named Express application and router receivers", () => {
  const facts = extractTypeScriptFacts(
    source(
      "src/api.ts",
      `const api = Router();
       api.post('/files', requireAuth, async (req: any, res: any) => {
         await db.file.create({ data: req.body });
         res.end();
       });`
    ),
    "express"
  );
  expect(facts.entrypoints).toHaveLength(1);
  expect(facts.entrypoints[0]?.path).toBe("/files");
  expect(facts.entrypoints[0]?.controls.some((control) => control.type === "authentication")).toBe(
    true
  );
  expect(facts.entrypoints[0]?.operations[0]?.metadata.userControlled).toBe(true);
});

it("preserves multiple security-relevant operations placed on the same source line", () => {
  const facts = extractTypeScriptFacts(
    source(
      "app/api/batch/route.ts",
      `export async function POST(request: Request) { const body = await request.json(); await prisma.item.create({ data: body }); await prisma.audit.create({ data: body }); return Response.json({ ok: true }); }`
    ),
    "nextjs"
  );
  const writes = facts.entrypoints[0]?.operations.filter(
    (operation) => operation.kind === "database"
  );
  expect(writes).toHaveLength(2);
  expect(writes?.map((operation) => operation.metadata.model)).toEqual(["item", "audit"]);
});

it("normalizes optional Next.js catch-all route segments", () => {
  const facts = extractTypeScriptFacts(
    source(
      "app/api/docs/[[...slug]]/route.ts",
      `export async function GET(){ return Response.json({ ok: true }); }`
    ),
    "nextjs"
  );
  expect(facts.entrypoints[0]?.path).toBe("/api/docs/*slug?");
});
