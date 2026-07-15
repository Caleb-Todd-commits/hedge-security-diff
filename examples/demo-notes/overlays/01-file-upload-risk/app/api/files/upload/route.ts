import { PutObjectCommand } from "@aws-sdk/client-s3";
import { evaluateUpload } from "../../../../lib/upload-policy.js";

export async function POST(request: Request) {
  const form = await request.formData();
  const file = form.get("file") as File;
  const decision = evaluateUpload({
    authenticated: false,
    ownerId: "",
    type: file.type,
    size: file.size
  });
  await client.send(
    new PutObjectCommand({
      Bucket: process.env.UPLOAD_BUCKET,
      Key: decision.key,
      Body: file
    })
  );
  return Response.json({ ok: true });
}
