function rateLimit(_request: Request): void {
  // The concrete implementation is outside this held-out source pair.
}

export async function POST(request: Request) {
  rateLimit(request);
  const invitation = await request.json();
  return Response.json({ queuedFor: invitation.email }, { status: 202 });
}
