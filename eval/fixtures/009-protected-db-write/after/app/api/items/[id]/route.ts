export async function PATCH(request: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const userId = session.user.id;
  const id = new URL(request.url).pathname.split("/").pop();
  await prisma.item.update({ where: { id, userId }, data: await request.json() });
  return Response.json({ ok: true });
}
