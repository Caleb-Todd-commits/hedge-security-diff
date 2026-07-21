import { execFile } from "node:child_process";
import { lstat, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

const root = resolve(process.argv[2] ?? ".");
const excludedFiles = new Set(["MANIFEST.md"]);
const files = [];
const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
const execFileAsync = promisify(execFile);

const { stdout } = await execFileAsync(
  "git",
  ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
  { cwd: root, maxBuffer: 16 * 1024 * 1024 }
);
for (const path of stdout.split("\0").filter(Boolean)) {
  if (excludedFiles.has(path)) continue;
  let stat;
  try {
    stat = await lstat(join(root, path));
  } catch (error) {
    if (error?.code === "ENOENT") continue;
    throw error;
  }
  if (stat.isSymbolicLink()) throw new Error(`Refusing symbolic link in release tree: ${path}`);
  if (stat.isFile()) files.push({ path, bytes: stat.size });
}
files.sort((a, b) => a.path.localeCompare(b.path));
const totalBytes = files.reduce((sum, file) => sum + file.bytes, 0);
const lines = [
  "# Package manifest",
  "",
  "> Generated from Git-tracked and non-ignored project files. Local secrets, build output, and this manifest file are excluded from the listing.",
  "",
  `- Version: ${packageJson.version}`,
  `- Files: ${files.length}`,
  `- Uncompressed bytes: ${totalBytes}`,
  "",
  "| File | Bytes |",
  "| --- | ---: |",
  ...files.map((file) => `| \`${escapeCell(file.path)}\` | ${file.bytes} |`),
  ""
];
await writeFile(join(root, "MANIFEST.md"), lines.join("\n"), "utf8");

function escapeCell(value) {
  return value.replaceAll("|", "\\|");
}
