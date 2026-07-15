export function GET() {
  return Response.json({ region: process.env.PUBLIC_REGION, bucket: process.env.UPLOAD_BUCKET });
}
