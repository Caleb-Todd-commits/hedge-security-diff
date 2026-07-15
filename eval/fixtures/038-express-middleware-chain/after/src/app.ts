function authenticate(req: any, _res: any, next: any) {
  requireAuth(req);
  next();
}
function adminOnly(req: any, _res: any, next: any) {
  requireRole(req, "admin");
  next();
}
async function create(req: any, res: any) {
  await db.item.create({ data: req.body });
  res.end();
}
app.use(authenticate);
app.post("/admin/items", adminOnly, create);
