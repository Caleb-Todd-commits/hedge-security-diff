export async function DELETE(request: Request) {
  const path = new URL(request.url).pathname;
  await prisma.cache.deleteMany({ where: { path } });
  return Response.json({ ok: true });
}
