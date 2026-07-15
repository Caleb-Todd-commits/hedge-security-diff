async function create(request: Request) {
  const body = await request.json();
  await prisma.item.create({ data: body });
  return Response.json({ ok: true });
}
export const POST = withAuth(create);
