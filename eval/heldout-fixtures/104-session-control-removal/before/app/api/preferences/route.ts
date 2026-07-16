function requireAuth(_request: Request): void {
  // The concrete implementation is outside this held-out source pair.
}

export async function PATCH(request: Request) {
  requireAuth(request);
  const preferences = await request.json();
  return Response.json({ saved: Boolean(preferences) });
}
