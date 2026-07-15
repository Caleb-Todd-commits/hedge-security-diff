"use server";
export async function updateAccount(input: { id: string; name: string }) {
  await prisma.account.update({ where: { id: input.id }, data: { name: input.name } });
}
