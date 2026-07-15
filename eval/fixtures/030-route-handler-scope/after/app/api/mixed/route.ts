async function helper() {
  const session = await auth();
  return session;
}
export async function POST(request: Request) {
  await prisma.note.create({ data: await request.json() });
  return Response.json({ ok: true });
}
