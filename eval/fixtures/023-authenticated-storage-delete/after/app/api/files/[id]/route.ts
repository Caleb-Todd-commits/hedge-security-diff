import { DeleteObjectCommand } from "@aws-sdk/client-s3";
export async function DELETE(request: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const userId = session.user.id;
  const id = new URL(request.url).pathname.split("/").pop();
  await client.send(new DeleteObjectCommand({ Key: `${userId}/${id}` }));
  return Response.json({ ok: true });
}
