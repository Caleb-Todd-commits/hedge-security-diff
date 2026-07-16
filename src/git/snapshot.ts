import { execFile } from "node:child_process";
import { realpath } from "node:fs/promises";
import { isAbsolute, relative } from "node:path";
import { promisify } from "node:util";
import type { HedgeConfig } from "../domain/schemas.js";
import {
  isIgnoredSourcePath,
  isSupportedSourcePath,
  relevanceScore,
  type SourceCollectionResult,
  type SourceFile
} from "../analyzers/files.js";

const execFileAsync = promisify(execFile);
const DEFAULT_MAX_TREE_OUTPUT_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_TREE_ENTRIES = 250_000;
const MAX_REVISION_LENGTH = 256;
const MAX_PATH_BYTES = 4_096;

export type GitSnapshotErrorCode =
  | "invalid-revision"
  | "not-a-repository"
  | "revision-not-found"
  | "tree-output-limit"
  | "tree-entry-limit"
  | "malformed-tree"
  | "blob-read-failed";

export class GitSnapshotError extends Error {
  readonly code: GitSnapshotErrorCode;

  constructor(code: GitSnapshotErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "GitSnapshotError";
    this.code = code;
  }
}

export interface GitTreeEntry {
  mode: string;
  type: string;
  objectId: string;
  size: number | undefined;
  path: string;
}

export interface ParsedGitTree {
  entries: GitTreeEntry[];
  rejectedUnsafePaths: number;
}

export interface GitSnapshotInventoryOptions {
  root: string;
  revision: string;
  config: HedgeConfig;
  maxTreeOutputBytes?: number;
  maxTreeEntries?: number;
}

export interface GitSnapshotInventoryResult {
  repositoryRoot: string;
  commit: string;
  inventory: SourceCollectionResult;
}

/**
 * Reads an exact Git commit without checking it out. Only built-in object database
 * commands are used, so checkout hooks, clean/smudge filters, and repository code
 * are never invoked.
 */
export async function collectGitSourceFileInventory(
  options: GitSnapshotInventoryOptions
): Promise<GitSnapshotInventoryResult> {
  const repositoryRoot = await resolveGitRepositoryRoot(options.root);
  const commit = await resolveGitCommit(repositoryRoot, options.revision);
  const parsedTree = await readGitTree(repositoryRoot, commit, {
    maxOutputBytes: options.maxTreeOutputBytes ?? DEFAULT_MAX_TREE_OUTPUT_BYTES,
    maxEntries: options.maxTreeEntries ?? DEFAULT_MAX_TREE_ENTRIES
  });

  const candidates = parsedTree.entries
    .filter(
      (entry) =>
        isSupportedSourcePath(entry.path) &&
        !isIgnoredSourcePath(entry.path, options.config.ignored_paths)
    )
    .sort(
      (a, b) => relevanceScore(b.path) - relevanceScore(a.path) || a.path.localeCompare(b.path)
    );

  const files: SourceFile[] = [];
  let includedBytes = 0;
  let omittedByFileLimit = 0;
  let omittedByByteLimit = 0;
  let omittedUnsafeOrUnreadable = parsedTree.rejectedUnsafePaths;
  let omittedBinary = 0;

  for (const entry of candidates) {
    if (files.length >= options.config.limits.max_files) {
      omittedByFileLimit += 1;
      continue;
    }

    if (!isReadableRegularBlob(entry)) {
      omittedUnsafeOrUnreadable += 1;
      continue;
    }

    if (includedBytes + entry.size > options.config.limits.max_bytes) {
      omittedByByteLimit += 1;
      continue;
    }

    const bytes = await readGitBlob(repositoryRoot, entry.objectId, entry.size);
    if (bytes.includes(0)) {
      omittedBinary += 1;
      continue;
    }
    let content: string;
    try {
      content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      omittedBinary += 1;
      continue;
    }

    includedBytes += entry.size;
    files.push({
      path: entry.path,
      absolutePath: `git-object:${entry.objectId}`,
      content,
      bytes: entry.size,
      commit
    });
  }

  return {
    repositoryRoot,
    commit,
    inventory: {
      files,
      stats: {
        discoveredFiles: candidates.length + parsedTree.rejectedUnsafePaths,
        includedFiles: files.length,
        includedBytes,
        omittedByFileLimit,
        omittedByByteLimit,
        omittedUnsafeOrUnreadable,
        omittedBinary
      }
    }
  };
}

export async function resolveGitCommit(root: string, revision: string): Promise<string> {
  assertSafeRevision(revision);
  try {
    const { stdout } = await execGitText(
      root,
      ["rev-parse", "--verify", "--end-of-options", `${revision}^{commit}`],
      1_024
    );
    const commit = stdout.trim().toLowerCase();
    if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(commit)) {
      throw new GitSnapshotError(
        "revision-not-found",
        "The Git revision did not resolve to a canonical commit object."
      );
    }
    return commit;
  } catch (error) {
    if (error instanceof GitSnapshotError) throw error;
    throw new GitSnapshotError(
      "revision-not-found",
      "The Git revision could not be resolved to a commit in this repository.",
      { cause: error }
    );
  }
}

export function parseGitTreeOutput(output: string, maxEntries: number): ParsedGitTree {
  const records = output.split("\0");
  if (records.at(-1) === "") records.pop();
  if (records.length > maxEntries) {
    throw new GitSnapshotError(
      "tree-entry-limit",
      `The Git tree contains more than the permitted ${maxEntries} entries.`
    );
  }

  const entries: GitTreeEntry[] = [];
  let rejectedUnsafePaths = 0;
  for (const record of records) {
    const separator = record.indexOf("\t");
    if (separator < 0) {
      throw new GitSnapshotError("malformed-tree", "Git returned a malformed tree entry.");
    }
    const metadata = record.slice(0, separator);
    const path = record.slice(separator + 1);
    const match = /^(\d{6}) ([a-z]+) ([0-9a-fA-F]{40}|[0-9a-fA-F]{64}) +(-|\d+)$/.exec(metadata);
    if (!match) {
      throw new GitSnapshotError("malformed-tree", "Git returned malformed tree metadata.");
    }
    if (!isSafeGitPath(path)) {
      rejectedUnsafePaths += 1;
      continue;
    }
    const rawSize = match[4];
    const size = rawSize === "-" ? undefined : Number(rawSize);
    if (size !== undefined && (!Number.isSafeInteger(size) || size < 0)) {
      throw new GitSnapshotError("malformed-tree", "Git returned an invalid blob size.");
    }
    entries.push({
      mode: match[1]!,
      type: match[2]!,
      objectId: match[3]!.toLowerCase(),
      size,
      path
    });
  }
  return { entries, rejectedUnsafePaths };
}

function assertSafeRevision(revision: string): void {
  if (
    revision.length === 0 ||
    revision.length > MAX_REVISION_LENGTH ||
    revision.startsWith("-") ||
    /[\0\r\n\s]/.test(revision)
  ) {
    throw new GitSnapshotError(
      "invalid-revision",
      "The Git revision is empty, too long, or contains unsupported characters."
    );
  }
}

async function resolveGitRepositoryRoot(root: string): Promise<string> {
  let canonicalInput: string;
  try {
    canonicalInput = await realpath(root);
  } catch (error) {
    throw new GitSnapshotError("not-a-repository", "The repository root is unavailable.", {
      cause: error
    });
  }

  try {
    const { stdout } = await execGitText(
      canonicalInput,
      ["rev-parse", "--show-toplevel"],
      16 * 1_024
    );
    const repositoryRoot = await realpath(stdout.trim());
    const fromRoot = relative(repositoryRoot, canonicalInput);
    if (isAbsolute(fromRoot) || fromRoot.startsWith("..")) {
      throw new Error("Git returned a repository root outside the requested working tree.");
    }
    return repositoryRoot;
  } catch (error) {
    throw new GitSnapshotError(
      "not-a-repository",
      "The requested directory is not inside a readable Git working tree.",
      { cause: error }
    );
  }
}

async function readGitTree(
  root: string,
  commit: string,
  limits: { maxOutputBytes: number; maxEntries: number }
): Promise<ParsedGitTree> {
  if (!Number.isSafeInteger(limits.maxOutputBytes) || limits.maxOutputBytes <= 0) {
    throw new GitSnapshotError("tree-output-limit", "The Git tree output limit must be positive.");
  }
  if (!Number.isSafeInteger(limits.maxEntries) || limits.maxEntries <= 0) {
    throw new GitSnapshotError("tree-entry-limit", "The Git tree entry limit must be positive.");
  }
  try {
    const { stdout } = await execGitText(
      root,
      ["ls-tree", "-r", "-z", "-l", "--full-tree", commit],
      limits.maxOutputBytes
    );
    return parseGitTreeOutput(stdout, limits.maxEntries);
  } catch (error) {
    if (error instanceof GitSnapshotError) throw error;
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") {
      throw new GitSnapshotError(
        "tree-output-limit",
        `The Git tree exceeded the permitted ${limits.maxOutputBytes} byte output budget.`,
        { cause: error }
      );
    }
    throw new GitSnapshotError("malformed-tree", "The exact Git tree could not be read.", {
      cause: error
    });
  }
}

function isReadableRegularBlob(entry: GitTreeEntry): entry is GitTreeEntry & { size: number } {
  return (
    entry.type === "blob" &&
    (entry.mode === "100644" || entry.mode === "100755") &&
    entry.size !== undefined
  );
}

function isSafeGitPath(path: string): boolean {
  if (
    path.length === 0 ||
    Buffer.byteLength(path, "utf8") > MAX_PATH_BYTES ||
    path.startsWith("/") ||
    path.includes("\\") ||
    path.includes("\ufffd") ||
    /[\u0000-\u001f\u007f]/.test(path)
  ) {
    return false;
  }
  const segments = path.split("/");
  if (
    segments.some((segment) => segment === "" || segment === "." || segment === "..") ||
    segments.some((segment) => segment.toLowerCase() === ".git") ||
    /^[a-zA-Z]:$/.test(segments[0] ?? "")
  ) {
    return false;
  }
  return true;
}

async function readGitBlob(root: string, objectId: string, expectedBytes: number): Promise<Buffer> {
  try {
    const { stdout } = await execGitBuffer(
      root,
      ["cat-file", "blob", objectId],
      Math.max(expectedBytes + 1_024, 1_024)
    );
    if (stdout.length !== expectedBytes) {
      throw new Error("Git blob length did not match the tree entry.");
    }
    return stdout;
  } catch (error) {
    throw new GitSnapshotError(
      "blob-read-failed",
      "A bounded source blob from the exact Git snapshot could not be read.",
      { cause: error }
    );
  }
}

function gitEnvironment(): NodeJS.ProcessEnv {
  const environment = { ...process.env };
  for (const key of Object.keys(environment)) {
    if (key.startsWith("GIT_")) delete environment[key];
  }
  return {
    ...environment,
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_LAZY_FETCH: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0"
  };
}

async function execGitText(
  cwd: string,
  args: string[],
  maxBuffer: number
): Promise<{ stdout: string; stderr: string }> {
  return execFileAsync("git", args, {
    cwd,
    encoding: "utf8",
    env: gitEnvironment(),
    maxBuffer,
    timeout: 30_000,
    windowsHide: true
  });
}

async function execGitBuffer(
  cwd: string,
  args: string[],
  maxBuffer: number
): Promise<{ stdout: Buffer; stderr: Buffer }> {
  return new Promise((resolvePromise, rejectPromise) => {
    execFile(
      "git",
      args,
      {
        cwd,
        encoding: "buffer",
        env: gitEnvironment(),
        maxBuffer,
        timeout: 30_000,
        windowsHide: true
      },
      (error, stdout, stderr) => {
        if (error) rejectPromise(error);
        else resolvePromise({ stdout, stderr });
      }
    );
  });
}
