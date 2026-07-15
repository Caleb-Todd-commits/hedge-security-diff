export async function POST(request: Request) {
  const input = await request.json();
  await fetch(input.url);
  exec(input.command);
  return Response.json({ ok: true });
}
