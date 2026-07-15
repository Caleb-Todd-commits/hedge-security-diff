export async function DELETE(request: Request) {
  const id = new URL(request.url).searchParams.get("id");
  await prisma.user.delete({ where: { id } });
  return Response.json({ deleted: true });
}
