import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface GitDiffResult {
  base: string;
  head: string;
  files: string[];
  patch: string;
  truncated: boolean;
}

export async function getGitDiff(
  cwd: string,
  base = "HEAD~1",
  head = "HEAD",
  maxBytes = 180_000
): Promise<GitDiffResult> {
  const [nameOnly, patchResult] = await Promise.all([
    execFileAsync("git", ["diff", "--name-only", `${base}...${head}`], {
      cwd,
      maxBuffer: 2_000_000
    }),
    execFileAsync("git", ["diff", "--no-ext-diff", "--unified=3", `${base}...${head}`], {
      cwd,
      maxBuffer: Math.max(maxBytes * 2, 2_000_000)
    })
  ]);

  const rawPatch = patchResult.stdout;
  const truncated = Buffer.byteLength(rawPatch, "utf8") > maxBytes;
  const patch = truncated ? Buffer.from(rawPatch).subarray(0, maxBytes).toString("utf8") : rawPatch;

  return {
    base,
    head,
    files: nameOnly.stdout
      .split("\n")
      .map((value) => value.trim())
      .filter(Boolean),
    patch,
    truncated
  };
}

export async function getCurrentCommit(cwd: string): Promise<string> {
  const { stdout } = await execFileAsync("git", ["rev-parse", "HEAD"], { cwd });
  return stdout.trim();
}
