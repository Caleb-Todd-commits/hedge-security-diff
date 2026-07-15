export async function GET(request: Request) {
  const city = new URL(request.url).searchParams.get("city");
  const response = await fetch(
    `https://weather.example.test?q=${city}&key=${process.env.WEATHER_API_KEY}`
  );
  return Response.json(await response.json());
}
