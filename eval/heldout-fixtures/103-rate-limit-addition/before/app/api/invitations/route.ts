export async function POST(request: Request) {
  const invitation = await request.json();
  return Response.json({ queuedFor: invitation.email }, { status: 202 });
}
