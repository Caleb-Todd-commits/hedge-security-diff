export async function GET() {
  const instant = new Date().toISOString();
  return Response.json({ instant });
}
