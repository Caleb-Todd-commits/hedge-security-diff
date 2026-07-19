import { PutObjectCommand } from "@aws-sdk/client-s3";

export default async function handler(req: any, res: any) {
  const file = req.body.file;
  await client.send(
    new PutObjectCommand({ Bucket: process.env.UPLOAD_BUCKET, Key: "upload", Body: file })
  );
  res.status(200).json({ ok: true });
}
