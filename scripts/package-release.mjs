import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const root = fileURLToPath(new URL("..", import.meta.url));
const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
const version = packageJson.version;
const releaseName = `hedge-v${version}`;
const releaseDirectory = join(root, "dist", "release");
const temporaryRoot = await mkdtemp(join(tmpdir(), "hedge-release-package-"));
const packageRoot = join(temporaryRoot, releaseName);

try {
  await rm(releaseDirectory, { recursive: true, force: true });
  await mkdir(releaseDirectory, { recursive: true });
  await mkdir(packageRoot, { recursive: true });

  const paths = [
    "LICENSE",
    "README.md",
    "action.yml",
    "dist/action/index.cjs",
    "dist/cli/index.cjs",
    "dist/workflows",
    "schemas"
  ];
  for (const path of paths) {
    await cp(join(root, path), join(packageRoot, path), { recursive: true });
  }

  const sourceCommit = (await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: root })).stdout
    .trim()
    .toLowerCase();
  const internalFiles = await inventory(packageRoot);
  await writeFile(
    join(packageRoot, "RELEASE-MANIFEST.json"),
    `${JSON.stringify(
      { schemaVersion: "hedge-release-v0.1", version, sourceCommit, files: internalFiles },
      null,
      2
    )}\n`,
    "utf8"
  );

  const bundleName = `${releaseName}-bundles.zip`;
  const bundlePath = join(releaseDirectory, bundleName);
  await execFileAsync("zip", ["-X", "-q", "-r", bundlePath, releaseName], {
    cwd: temporaryRoot
  });

  const dashboardName = "security-diff.html";
  await cp(
    join(root, "examples", "demo-output", dashboardName),
    join(releaseDirectory, dashboardName)
  );

  const assets = [];
  for (const name of [bundleName, dashboardName]) {
    assets.push({ name, ...(await fileRecord(join(releaseDirectory, name))) });
  }
  const manifestName = "manifest.json";
  await writeFile(
    join(releaseDirectory, manifestName),
    `${JSON.stringify(
      {
        schemaVersion: "hedge-release-assets-v0.1",
        version,
        sourceCommit,
        assets,
        bundleFiles: internalFiles
      },
      null,
      2
    )}\n`,
    "utf8"
  );

  const checksumTargets = [bundleName, manifestName, dashboardName];
  const checksums = [];
  for (const name of checksumTargets) {
    const record = await fileRecord(join(releaseDirectory, name));
    checksums.push(`${record.sha256}  ${name}`);
  }
  await writeFile(
    join(releaseDirectory, `${releaseName}-SHA256SUMS`),
    `${checksums.join("\n")}\n`,
    "utf8"
  );

  process.stdout.write(`${releaseDirectory}\n`);
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

async function inventory(directory) {
  const files = [];
  await walk(directory, "");
  return files.sort((left, right) => left.path.localeCompare(right.path));

  async function walk(current, relative) {
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const entryPath = join(current, entry.name);
      const relativePath = join(relative, entry.name).replaceAll("\\", "/");
      if (entry.isDirectory()) {
        await walk(entryPath, relativePath);
        continue;
      }
      if (!entry.isFile()) throw new Error(`Refusing non-file release entry: ${relativePath}`);
      files.push({ path: relativePath, ...(await fileRecord(entryPath)) });
    }
  }
}

async function fileRecord(path) {
  const bytes = await readFile(path);
  const details = await stat(path);
  return {
    bytes: details.size,
    sha256: createHash("sha256").update(bytes).digest("hex")
  };
}
