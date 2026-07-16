export async function GET(request: Request) {
  const session = await auth(request);
  if (!session) return new Response("Unauthorized", { status: 401 });
  const notes = await prisma.note.findMany({ where: { ownerId: session.user.id } });
  return Response.json(notes);
}

async function auth(request: Request) {
  const userId = request.headers.get("x-demo-user-id");
  return userId ? { user: { id: userId } } : null;
}
