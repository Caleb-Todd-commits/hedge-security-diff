import { PutObjectCommand } from "@aws-sdk/client-s3";
import { evaluateUpload } from "../../../../lib/upload-policy.js";

export async function POST(request: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const form = await request.formData();
  const file = form.get("file") as File;
  const allowedTypes = ["image/png", "image/jpeg"];
  const maxFileSize = 5_000_000;
  if (!allowedTypes.includes(file.type)) return new Response("Unsupported", { status: 415 });
  if (file.size > maxFileSize) return new Response("Too large", { status: 413 });
  const ownerId = session.user.id;
  const decision = evaluateUpload({
    authenticated: true,
    ownerId,
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
