import { PutObjectCommand } from "@aws-sdk/client-s3";
export async function POST(request: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const file = (await request.formData()).get("file") as File;
  const ownerId = session.user.id;
  await client.send(new PutObjectCommand({ Key: `${ownerId}/x`, Body: file }));
  return Response.json({ ok: true });
}
