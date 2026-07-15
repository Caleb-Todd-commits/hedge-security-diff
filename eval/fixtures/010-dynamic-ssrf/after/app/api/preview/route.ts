export async function GET(request: Request) {
  const target = new URL(request.url).searchParams.get("url");
  const response = await fetch(target!);
  return new Response(await response.text());
}
