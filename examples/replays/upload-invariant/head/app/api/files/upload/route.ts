export async function POST(request: Request) {
  const body = await request.formData();
  await prisma.file.create({
    data: { name: String(body.get("name")), ownerId: String(body.get("ownerId")) }
  });
  return Response.json({ ok: true });
}
