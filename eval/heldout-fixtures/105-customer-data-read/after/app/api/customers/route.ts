import { prisma } from "@/server/database";

export async function GET() {
  const customers = await prisma.customer.findMany({
    select: { id: true, email: true, billingAddress: true }
  });
  return Response.json({ customers });
}
