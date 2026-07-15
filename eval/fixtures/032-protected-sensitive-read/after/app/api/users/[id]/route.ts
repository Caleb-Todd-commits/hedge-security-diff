export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const session = await auth();
  const { id } = await context.params;
  const user = await prisma.user.findFirst({ where: { id, tenantId: session.user.tenantId } });
  return Response.json(user);
}
