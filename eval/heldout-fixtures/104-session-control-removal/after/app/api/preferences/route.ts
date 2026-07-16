export async function PATCH(request: Request) {
  const preferences = await request.json();
  return Response.json({ saved: Boolean(preferences) });
}
