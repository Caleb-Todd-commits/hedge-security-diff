export async function GET() {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const notes = await prisma.note.findMany({ where: { ownerId: session.user.id } });
  return Response.json(notes);
}
