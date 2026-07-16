export async function GET() {
  const response = await fetch("https://metadata.example.test/default-card.json");
  return Response.json(await response.json());
}
