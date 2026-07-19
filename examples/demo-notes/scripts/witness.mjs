import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const policyUrl = pathToFileURL(resolve(process.cwd(), "lib/upload-policy.js")).href;
const { evaluateUpload } = await import(policyUrl);

const result = evaluateUpload({
  authenticated: false,
  ownerId: "",
  type: "application/x-executable",
  size: 50_000_000
});

const outcome = result.accepted
  ? {
      outcome: "reproduced",
      reason: "Unauthenticated, oversized executable content was accepted."
    }
  : {
      outcome: "blocked-by-control",
      reason: "The intended upload controls rejected the witness."
    };
const serialized = `${JSON.stringify(outcome)}\n`;

if (process.env.HEDGE_OUTCOME_PATH) {
  writeFileSync(process.env.HEDGE_OUTCOME_PATH, serialized, {
    encoding: "utf8",
    mode: 0o600
  });
}
process.stdout.write(serialized);
