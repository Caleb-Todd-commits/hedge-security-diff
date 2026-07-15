import { execFile } from "node:child_process";
export async function POST(request: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  execFile("git", ["status"]);
  return Response.json({ ok: true });
}
