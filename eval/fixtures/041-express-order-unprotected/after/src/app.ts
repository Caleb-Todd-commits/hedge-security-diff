app.post("/items", async (req: any, res: any) => {
  await db.item.create({ data: req.body });
  res.end();
});
app.use(requireAuth);
