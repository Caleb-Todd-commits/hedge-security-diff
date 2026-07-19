import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const root = fileURLToPath(new URL("..", import.meta.url));
const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
const releaseName = `hedge-v${packageJson.version}`;
const releaseDirectory = join(root, "dist", "release");
const bundleName = `${releaseName}-bundles.zip`;
const checksumName = `${releaseName}-SHA256SUMS`;
const temporaryRoot = await mkdtemp(join(tmpdir(), "hedge-release-smoke-"));
const repositoryRoot = join(temporaryRoot, "repository");
const startedAt = Date.now();

try {
  await verifyChecksums(releaseDirectory, checksumName);
  await execFileAsync("unzip", ["-q", join(releaseDirectory, bundleName), "-d", temporaryRoot]);
  const cli = join(temporaryRoot, releaseName, "dist", "cli", "index.cjs");
  await execFileAsync(process.execPath, [cli, "--help"]);

  await mkdir(repositoryRoot, { recursive: true });
  await execFileAsync("git", ["init", "--quiet"], { cwd: repositoryRoot });
  await execFileAsync("git", ["config", "user.name", "Hedge release smoke test"], {
    cwd: repositoryRoot
  });
  await execFileAsync("git", ["config", "user.email", "hedge-release@example.invalid"], {
    cwd: repositoryRoot
  });

  await execFileAsync(
    process.execPath,
    [
      cli,
      "install",
      "--root",
      repositoryRoot,
      "--action-ref",
      "example/hedge@0123456789012345678901234567890123456789",
      "--full"
    ],
    { cwd: repositoryRoot }
  );
  await writeFile(
    join(repositoryRoot, "package.json"),
    `${JSON.stringify({ private: true, dependencies: { next: "latest" } }, null, 2)}\n`,
    "utf8"
  );
  await mkdir(join(repositoryRoot, "app", "api", "health"), { recursive: true });
  await writeFile(
    join(repositoryRoot, "app", "api", "health", "route.ts"),
    "export async function GET() { return Response.json({ ok: true }); }\n",
    "utf8"
  );
  await execFileAsync("git", ["add", "."], { cwd: repositoryRoot });
  await execFileAsync("git", ["commit", "--quiet", "-m", "baseline"], { cwd: repositoryRoot });

  await mkdir(join(repositoryRoot, "app", "api", "files", "upload"), { recursive: true });
  await writeFile(
    join(repositoryRoot, "app", "api", "files", "upload", "route.ts"),
    [
      'import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";',
      "const client = new S3Client({});",
      "export async function POST(request: Request) {",
      "  const body = await request.arrayBuffer();",
      '  await client.send(new PutObjectCommand({ Bucket: process.env.UPLOAD_BUCKET, Key: "upload", Body: body }));',
      "  return Response.json({ ok: true });",
      "}",
      ""
    ].join("\n"),
    "utf8"
  );
  await execFileAsync("git", ["add", "."], { cwd: repositoryRoot });
  await execFileAsync("git", ["commit", "--quiet", "-m", "add upload route"], {
    cwd: repositoryRoot
  });

  const doctor = await execFileAsync(process.execPath, [cli, "doctor", "--root", repositoryRoot], {
    cwd: repositoryRoot
  });
  if (!doctor.stdout.includes("Repository surface compatibility")) {
    throw new Error("Packaged doctor did not report repository surface compatibility.");
  }
  await execFileAsync(
    process.execPath,
    [cli, "check", "--root", repositoryRoot, "--base", "HEAD~1", "--head", "HEAD", "--offline"],
    { cwd: repositoryRoot }
  );
  const analysis = JSON.parse(
    await readFile(join(repositoryRoot, ".hedge", "analysis.json"), "utf8")
  );
  if (!analysis.surfaceChanged || analysis.findings.length < 1) {
    throw new Error("Packaged offline check did not surface the expected architecture change.");
  }
  if (Date.now() - startedAt >= 10 * 60 * 1000) {
    throw new Error("Packaged installation smoke test exceeded ten minutes.");
  }

  process.stdout.write("Packaged release validation passed.\n");
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

async function verifyChecksums(directory, checksumFile) {
  const text = await readFile(join(directory, checksumFile), "utf8");
  for (const line of text.trim().split("\n")) {
    const match = /^([a-f0-9]{64})  ([A-Za-z0-9._-]+)$/.exec(line);
    if (!match) throw new Error(`Invalid checksum line: ${line}`);
    const bytes = await readFile(join(directory, match[2]));
    const actual = createHash("sha256").update(bytes).digest("hex");
    if (actual !== match[1]) throw new Error(`Checksum mismatch for ${match[2]}`);
  }
}
