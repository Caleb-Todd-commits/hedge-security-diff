async function handler(request: Request) {
  await prisma.note.create({ data: await request.json() });
  return Response.json({ ok: true });
}
export { handler as POST };
