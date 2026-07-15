export async function GET(request: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const userId = session.user.id;
  const id = new URL(request.url).pathname.split("/").pop();
  return Response.json(await prisma.note.findFirst({ where: { id, userId } }));
}
