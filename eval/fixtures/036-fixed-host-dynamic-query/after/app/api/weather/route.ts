export async function GET(request: Request) {
  const city = new URL(request.url).searchParams.get("city");
  const response = await fetch(`https://weather.example.test/search?q=${city}`);
  return Response.json(await response.json());
}
