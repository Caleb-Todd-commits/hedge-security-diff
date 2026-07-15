export function evaluateUpload({ authenticated, ownerId, type, size }) {
  return {
    accepted: Boolean(
      authenticated && ownerId && ["image/png", "image/jpeg"].includes(type) && size <= 5_000_000
    ),
    key: ownerId ? `${ownerId}/upload` : "upload"
  };
}
