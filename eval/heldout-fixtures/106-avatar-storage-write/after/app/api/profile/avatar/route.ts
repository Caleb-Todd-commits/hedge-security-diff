import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";

const storage = new S3Client({});

export async function PUT(request: Request) {
  const bytes = await request.arrayBuffer();
  await storage.send(
    new PutObjectCommand({ Bucket: "profile-images", Key: crypto.randomUUID(), Body: bytes })
  );
  return Response.json({ stored: true }, { status: 201 });
}
