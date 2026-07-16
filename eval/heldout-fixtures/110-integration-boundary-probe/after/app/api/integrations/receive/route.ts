export async function POST(request: Request) {
  const event = await request.json();
  return Response.json({ receivedType: event.type }, { status: 202 });
}
