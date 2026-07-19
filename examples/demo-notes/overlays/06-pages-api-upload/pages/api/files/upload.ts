import { PutObjectCommand } from "@aws-sdk/client-s3";
import type { NextApiRequest, NextApiResponse } from "next";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await client.send(
    new PutObjectCommand({
      Bucket: process.env.UPLOAD_BUCKET,
      Key: "upload",
      Body: req.body
    })
  );
  res.status(200).json({ ok: true });
}
