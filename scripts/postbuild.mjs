import { chmod, copyFile, mkdir, readFile, writeFile } from "node:fs/promises";

const cliPath = new URL("../dist/cli/index.cjs", import.meta.url);
const content = await readFile(cliPath, "utf8");
if (!content.startsWith("#!/usr/bin/env node")) {
  await writeFile(cliPath, `#!/usr/bin/env node\n${content}`);
}
await chmod(cliPath, 0o755);

const workflowNames = ["hedge.yml", "hedge-fix.yml", "hedge-verify.yml"];
const workflowDirectory = new URL("../dist/workflows/", import.meta.url);
await mkdir(workflowDirectory, { recursive: true });
for (const name of workflowNames) {
  await copyFile(
    new URL(`../examples/workflows/${name}`, import.meta.url),
    new URL(name, workflowDirectory)
  );
}
