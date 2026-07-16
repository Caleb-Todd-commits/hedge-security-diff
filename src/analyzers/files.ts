import { lstat, readFile, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";
import fg from "fast-glob";
import micromatch from "micromatch";
import type { HedgeConfig } from "../domain/schemas.js";

export const SOURCE_PATTERNS = [
  "**/*.{ts,tsx,js,jsx,mjs,cjs}",
  "**/package.json",
  "**/schema.prisma",
  "**/*.{yml,yaml,json,toml}"
];

export const DEFAULT_SOURCE_IGNORES = [
  "**/node_modules/**",
  "**/dist/**",
  "**/build/**",
  "**/.next/**",
  "**/coverage/**",
  "**/.git/**",
  "**/*.min.js",
  "**/package-lock.json",
  "**/pnpm-lock.yaml",
  "**/yarn.lock"
];

export interface SourceFile {
  path: string;
  absolutePath: string;
  content: string;
  bytes: number;
  commit?: string;
  snapshot?: "base" | "head";
}

export interface SourceCollectionStats {
  discoveredFiles: number;
  includedFiles: number;
  includedBytes: number;
  omittedByFileLimit: number;
  omittedByByteLimit: number;
  omittedUnsafeOrUnreadable: number;
  omittedBinary: number;
}

export interface SourceCollectionResult {
  files: SourceFile[];
  stats: SourceCollectionStats;
}

export async function collectSourceFiles(root: string, config: HedgeConfig): Promise<SourceFile[]> {
  return (await collectSourceFileInventory(root, config)).files;
}

export async function collectSourceFileInventory(
  root: string,
  config: HedgeConfig
): Promise<SourceCollectionResult> {
  const canonicalRoot = await realpath(root);
  const entries = await fg(SOURCE_PATTERNS, {
    cwd: canonicalRoot,
    onlyFiles: true,
    dot: true,
    unique: true,
    followSymbolicLinks: false,
    ignore: [...DEFAULT_SOURCE_IGNORES, ...config.ignored_paths]
  });

  const prioritized = entries.sort(
    (a, b) => relevanceScore(b) - relevanceScore(a) || a.localeCompare(b)
  );
  const result: SourceFile[] = [];
  let totalBytes = 0;
  let omittedByFileLimit = 0;
  let omittedByByteLimit = 0;
  let omittedUnsafeOrUnreadable = 0;
  let omittedBinary = 0;

  for (const entry of prioritized) {
    if (result.length >= config.limits.max_files) {
      omittedByFileLimit += 1;
      continue;
    }

    try {
      const absolutePath = resolve(canonicalRoot, entry);
      if (!isPathInside(canonicalRoot, absolutePath)) {
        omittedUnsafeOrUnreadable += 1;
        continue;
      }

      const metadata = await lstat(absolutePath);
      if (!metadata.isFile() || metadata.isSymbolicLink()) {
        omittedUnsafeOrUnreadable += 1;
        continue;
      }
      if (totalBytes + metadata.size > config.limits.max_bytes) {
        omittedByByteLimit += 1;
        continue;
      }

      const canonicalFile = await realpath(absolutePath);
      if (!isPathInside(canonicalRoot, canonicalFile)) {
        omittedUnsafeOrUnreadable += 1;
        continue;
      }

      const content = await readFile(canonicalFile, "utf8");
      if (content.includes("\0")) {
        omittedBinary += 1;
        continue;
      }

      totalBytes += metadata.size;
      result.push({
        path: relative(canonicalRoot, canonicalFile).replaceAll("\\", "/"),
        absolutePath: canonicalFile,
        content,
        bytes: metadata.size
      });
    } catch {
      // Repositories can contain broken links, permission-restricted paths, or files
      // removed during analysis. Record the coverage loss instead of crashing the run.
      omittedUnsafeOrUnreadable += 1;
    }
  }

  return {
    files: result,
    stats: {
      discoveredFiles: entries.length,
      includedFiles: result.length,
      includedBytes: totalBytes,
      omittedByFileLimit,
      omittedByByteLimit,
      omittedUnsafeOrUnreadable,
      omittedBinary
    }
  };
}

export function relevanceScore(path: string): number {
  const normalized = path.toLowerCase();
  let score = 0;
  if (/route\.(ts|js)x?$/.test(normalized)) score += 100;
  if (/middleware\.(ts|js)$/.test(normalized)) score += 95;
  if (/auth|session|permission|policy|access/.test(normalized)) score += 75;
  if (/api|routes?|controller|handler/.test(normalized)) score += 70;
  if (/prisma|schema|database|storage|upload/.test(normalized)) score += 65;
  if (/package\.json$/.test(normalized)) score += 55;
  if (/terraform|cloudformation|serverless|docker/.test(normalized)) score += 50;
  if (/test|spec|fixture/.test(normalized)) score -= 40;
  if (/docs?|readme/.test(normalized)) score -= 60;
  return score;
}

export function isSupportedSourcePath(path: string): boolean {
  return micromatch.isMatch(path, SOURCE_PATTERNS, {
    dot: true,
    nonegate: true
  });
}

export function isIgnoredSourcePath(path: string, ignoredPaths: readonly string[]): boolean {
  return micromatch.isMatch(path, [...DEFAULT_SOURCE_IGNORES, ...ignoredPaths], {
    dot: true,
    nonegate: true
  });
}

function isPathInside(root: string, candidate: string): boolean {
  const pathFromRoot = relative(root, candidate);
  return pathFromRoot === "" || (!pathFromRoot.startsWith("..") && !isAbsolute(pathFromRoot));
}
