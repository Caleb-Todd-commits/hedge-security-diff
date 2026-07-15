import { cp, mkdir, readdir, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const here = dirname(fileURLToPath(import.meta.url));
const template = resolve(here, "..");
const target = resolve(process.argv[2] ?? "/tmp/hedge-demo-notes");
const overlays = join(template, "overlays");

await rm(target, { recursive: true, force: true });
await mkdir(target, { recursive: true });
for (const entry of await readdir(template, { withFileTypes: true })) {
  if (["overlays", "scenarios", "node_modules", ".git"].includes(entry.name)) continue;
  await cp(join(template, entry.name), join(target, entry.name), { recursive: true });
}

run("git", ["init", "-b", "main"]);
run("git", ["config", "user.name", "Hedge Demo"]);
run("git", ["config", "user.email", "hedge-demo@example.test"]);
run("git", ["add", "."]);
run("git", ["commit", "-m", "demo: baseline notes application"]);

await branchFrom(
  "main",
  "demo/01-file-upload-risk",
  "01-file-upload-risk",
  "feat: add file upload endpoint"
);
await branchFrom(
  "main",
  "demo/02-benign-refactor",
  "02-benign-refactor",
  "refactor: add date formatter"
);
await branchFrom(
  "demo/01-file-upload-risk",
  "demo/03-upload-remediation",
  "03-upload-remediation",
  "fix: enforce upload security invariant"
);
await branchFrom(
  "main",
  "demo/04-admin-route",
  "04-admin-route",
  "feat: add user administration route"
);
await branchFrom(
  "main",
  "demo/05-injection-attempt",
  "05-injection-attempt",
  "test: add adversarial repository content"
);
run("git", ["switch", "main"]);
console.log(`Created demo repository at ${target}`);
console.log("Branches:");
console.log(run("git", ["branch", "--list"], true));

async function branchFrom(base, branch, overlay, message) {
  run("git", ["switch", base]);
  run("git", ["switch", "-c", branch]);
  await cp(join(overlays, overlay), target, { recursive: true });
  run("git", ["add", "."]);
  run("git", ["commit", "-m", message]);
}

function run(command, args, capture = false) {
  const result = execFileSync(command, args, {
    cwd: target,
    encoding: "utf8",
    stdio: capture ? "pipe" : "inherit"
  });
  return capture ? result.trim() : "";
}
