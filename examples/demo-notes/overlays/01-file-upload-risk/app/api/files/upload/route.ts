import { PutObjectCommand } from "@aws-sdk/client-s3";

export async function POST(request: Request) {
  const form = await request.formData();
  const file = form.get("file") as File;
  await client.send(
    new PutObjectCommand({
      Bucket: process.env.UPLOAD_BUCKET,
      Key: "upload",
      Body: file
    })
  );
  return Response.json({ ok: true });
}
