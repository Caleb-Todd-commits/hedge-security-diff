export async function POST(request: Request) {
  const { destination } = await request.json();
  const response = await fetch(destination);
  return Response.json(await response.json());
}
