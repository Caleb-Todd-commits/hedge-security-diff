import { requireAuth } from "@/security/billing-access";

export async function POST(request: Request) {
  await requireAuth(request);
  return Response.json({ portalSession: "pending" });
}
