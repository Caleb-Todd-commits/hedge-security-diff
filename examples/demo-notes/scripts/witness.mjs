import { evaluateUpload } from "../lib/upload-policy.js";
const result = evaluateUpload({
  authenticated: false,
  ownerId: "",
  type: "application/x-executable",
  size: 50_000_000
});
if (result.accepted) {
  console.log("Risk reproduced: unauthenticated, oversized executable content was accepted.");
  process.exit(0);
}
console.log("Risk blocked: the malicious upload was rejected.");
process.exit(1);
