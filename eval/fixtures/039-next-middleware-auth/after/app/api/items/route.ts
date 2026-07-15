export async function POST(request: Request) {
  const body = await request.json();
  await prisma.item.create({ data: body });
  return Response.json({ ok: true });
}
