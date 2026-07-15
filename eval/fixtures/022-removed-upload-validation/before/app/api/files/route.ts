import { PutObjectCommand } from "@aws-sdk/client-s3";
export async function POST(request: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const file = (await request.formData()).get("file") as File;
  const allowedTypes = ["image/png"];
  if (!allowedTypes.includes(file.type)) return new Response("bad", { status: 415 });
  if (file.size > 1000000) return new Response("large", { status: 413 });
  const ownerId = session.user.id;
  await client.send(new PutObjectCommand({ Key: `${ownerId}/x`, Body: file }));
  return Response.json({ ok: true });
}
