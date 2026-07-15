app.use("/admin", requireAuth);
app.post("/public/items", async (req: any, res: any) => {
  await db.item.create({ data: req.body });
  res.end();
});
