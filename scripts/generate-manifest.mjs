import { lstat, readFile, readdir, writeFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";

const root = resolve(process.argv[2] ?? ".");
const excludedDirectories = new Set([".git", "node_modules", "coverage"]);
const excludedFiles = new Set(["MANIFEST.md"]);
const files = [];
const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8"));

await walk(root);
files.sort((a, b) => a.path.localeCompare(b.path));
const totalBytes = files.reduce((sum, file) => sum + file.bytes, 0);
const lines = [
  "# Package manifest",
  "",
  "> Generated from the distributable project tree. `node_modules`, `.git`, coverage output, and this manifest file are excluded from the listing.",
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

async function walk(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && excludedDirectories.has(entry.name)) continue;
    const absolute = join(directory, entry.name);
    const path = relative(root, absolute).replaceAll("\\", "/");
    if (entry.isDirectory()) {
      await walk(absolute);
      continue;
    }
    if (excludedFiles.has(path)) continue;
    const stat = await lstat(absolute);
    if (stat.isSymbolicLink()) throw new Error(`Refusing symbolic link in release tree: ${path}`);
    if (!stat.isFile()) continue;
    files.push({ path, bytes: stat.size });
  }
}

function escapeCell(value) {
  return value.replaceAll("|", "\\|");
}
