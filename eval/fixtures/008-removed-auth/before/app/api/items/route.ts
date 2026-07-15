export async function POST(request: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  await prisma.item.create({ data: await request.json() });
  return Response.json({ ok: true });
}
