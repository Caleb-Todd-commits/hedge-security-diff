export default async function handler(req: any, res: any) {
  await requireAuth(req);
  res.status(200).json({ ok: true, id: req.query.id });
}
