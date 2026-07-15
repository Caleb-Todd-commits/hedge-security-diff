export async function POST(request: Request) {
  await prisma.item.create({ data: await request.json() });
  return Response.json({ ok: true });
}
