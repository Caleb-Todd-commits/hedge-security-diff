export async function GET() {
  const token = process.env.PAYMENT_API_KEY;
  console.log("configured", token);
  return Response.json({ configured: Boolean(token) });
}
