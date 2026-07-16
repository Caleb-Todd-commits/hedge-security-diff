export async function GET() {
  const currentInstant = new Date().toISOString();
  return Response.json({ instant: currentInstant });
}
