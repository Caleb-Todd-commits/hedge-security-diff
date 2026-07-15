export async function POST(request: Request) {
  const payload = await request.json();
  await fetch(payload.callbackUrl, { method: "POST", body: JSON.stringify(payload) });
  return Response.json({ delivered: true });
}
