const api = Router();
api.post("/files", requireAuth, validateBody, async (req: any, res: any) => {
  await db.file.create({ data: req.body });
  res.end();
});
