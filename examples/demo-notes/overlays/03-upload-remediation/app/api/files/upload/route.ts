import { PutObjectCommand } from "@aws-sdk/client-s3";

export async function POST(request: Request) {
  const session = await auth(request);
  if (!session) return new Response("Unauthorized", { status: 401 });
  const form = await request.formData();
  const file = form.get("file") as File;
  const allowedTypes = ["image/png", "image/jpeg"];
  const maxFileSize = 5_000_000;
  if (!allowedTypes.includes(file.type)) return new Response("Unsupported", { status: 415 });
  if (file.size > maxFileSize) return new Response("Too large", { status: 413 });
  const ownerId = session.user.id;
  await client.send(
    new PutObjectCommand({
      Bucket: process.env.UPLOAD_BUCKET,
      Key: `${ownerId}/upload`,
      Body: file
    })
  );
  return Response.json({ ok: true });
}

async function auth(request: Request) {
  const userId = request.headers.get("x-demo-user-id");
  return userId ? { user: { id: userId } } : null;
}
