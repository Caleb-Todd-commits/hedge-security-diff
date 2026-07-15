import express from "express";
export const app = express();
async function createUser(req: any, res: any) {
  const user = await requireAuth(req);
  if (!user) return res.status(401).end();
  const accountId = user.accountId;
  await prisma.user.create({ data: { ...req.body, accountId } });
  res.json({ ok: true });
}
app.post("/users", createUser);
