export async function GET() {
  const response = await fetch("https://status.example.test/api");
  return Response.json(await response.json());
}
