export async function POST(request: Request) {
  const payload = await request.json();
  return Response.json({ accepted: typeof payload.message === "string" }, { status: 201 });
}
