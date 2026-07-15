import { evaluateUpload } from "../lib/upload-policy.js";
const result = evaluateUpload({
  authenticated: true,
  ownerId: "user-123",
  type: "image/png",
  size: 250_000
});
if (!result.accepted || !result.key.startsWith("user-123/")) {
  throw new Error("Legitimate owned PNG upload no longer works.");
}
console.log("Legitimate upload remains available and tenant-scoped.");
