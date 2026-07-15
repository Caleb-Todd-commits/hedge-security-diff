export async function DELETE(request: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  await requireRole(session, "admin");
  const id = new URL(request.url).searchParams.get("id");
  await prisma.user.delete({ where: { id } });
  return Response.json({ ok: true });
}
