export async function PATCH(request: Request) {
  const session = await auth();
  const id = new URL(request.url).pathname.split("/").pop();
  await prisma.account.update({ where: { id }, data: await request.json() });
  return Response.json({ ok: true });
}
