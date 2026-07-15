import { chmod, readFile, writeFile } from "node:fs/promises";

const cliPath = new URL("../dist/cli/index.cjs", import.meta.url);
const content = await readFile(cliPath, "utf8");
if (!content.startsWith("#!/usr/bin/env node")) {
  await writeFile(cliPath, `#!/usr/bin/env node\n${content}`);
}
await chmod(cliPath, 0o755);
