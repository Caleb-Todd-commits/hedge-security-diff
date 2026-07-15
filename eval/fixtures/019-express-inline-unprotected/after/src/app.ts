import express from "express";
export const app = express();
app.post("/users", async (req, res) => {
  await prisma.user.create({ data: req.body });
  res.json({ ok: true });
});
