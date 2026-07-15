export function evaluateUpload({ authenticated, ownerId, type, size }) {
  const accepted = Boolean(
    authenticated && ownerId && ["image/png", "image/jpeg"].includes(type) && size <= 5_000_000
  );
  return { accepted, key: ownerId ? `${ownerId}/upload` : "upload" };
}
