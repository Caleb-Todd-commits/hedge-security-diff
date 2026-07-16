import { createHash } from "node:crypto";

const DEFAULT_MAX_PATCH_BYTES = 256_000;
const DEFAULT_MAX_FILES = 40;
const REGULAR_FILE_MODES = new Set(["100644", "100755"]);
const GENERATED_FILES = new Set([
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "bun.lockb"
]);
const GENERATED_DIRECTORIES = [
  ".next/",
  ".turbo/",
  ".cache/",
  "node_modules/",
  "coverage/",
  "dist/",
  "build/",
  "out/"
];

export interface RemediationPatchPolicy {
  maxBytes?: number;
  maxFiles?: number;
  allowWorkflows?: boolean;
}

export interface ValidatedRemediationPatch {
  digest: string;
  byteLength: number;
  files: string[];
}

export interface RemediationPatchManifest extends ValidatedRemediationPatch {
  schemaVersion: "0.1";
  riskId: string;
  sourceCommit: string;
}

/** Validate a model-produced patch before it crosses into a write-authorized job. */
export function validateRemediationPatch(
  patch: string,
  policy: RemediationPatchPolicy = {}
): ValidatedRemediationPatch {
  const maxBytes = policy.maxBytes ?? DEFAULT_MAX_PATCH_BYTES;
  const maxFiles = policy.maxFiles ?? DEFAULT_MAX_FILES;
  const byteLength = Buffer.byteLength(patch, "utf8");
  if (!patch.trim()) throw new Error("The remediation patch is empty.");
  if (byteLength > maxBytes) {
    throw new Error(`The remediation patch is ${byteLength} bytes; limit is ${maxBytes}.`);
  }
  if (patch.includes("\0")) throw new Error("Binary/NUL patch content is not allowed.");
  if (/^GIT binary patch$/m.test(patch) || /^Binary files .+ differ$/m.test(patch)) {
    throw new Error("Binary patch content is not allowed.");
  }
  if (/^diff --cc |^diff --combined /m.test(patch)) {
    throw new Error("Combined merge diffs are not allowed.");
  }

  const chunks = patch.split(/(?=^diff --git )/m).filter((chunk) => chunk.trim());
  if (!chunks.length || chunks.some((chunk) => !chunk.startsWith("diff --git "))) {
    throw new Error("Only complete git diff patches are accepted.");
  }

  const files = new Set<string>();
  for (const chunk of chunks) {
    const paths = extractDeclaredPaths(chunk);
    if (!paths.length)
      throw new Error("A diff entry did not declare a source or destination path.");
    for (const path of paths) {
      validatePatchPath(path, policy.allowWorkflows ?? false);
      files.add(path);
    }
    validateFileModes(chunk);
  }
  if (files.size > maxFiles) {
    throw new Error(`The remediation patch changes ${files.size} files; limit is ${maxFiles}.`);
  }

  return {
    digest: createHash("sha256").update(patch, "utf8").digest("hex"),
    byteLength,
    files: [...files].sort()
  };
}

export function createRemediationPatchManifest(
  patch: string,
  options: RemediationPatchPolicy & { riskId: string; sourceCommit: string }
): RemediationPatchManifest {
  if (!/^HEDGE-\d{3,}$/.test(options.riskId)) {
    throw new Error("Remediation manifest requires a canonical HEDGE-NNN risk ID.");
  }
  if (!/^[a-f0-9]{40,64}$/.test(options.sourceCommit)) {
    throw new Error("Remediation manifest requires an exact source commit.");
  }
  return {
    schemaVersion: "0.1",
    riskId: options.riskId,
    sourceCommit: options.sourceCommit,
    ...validateRemediationPatch(patch, options)
  };
}

/** Bound model prose before it is published to GitHub. */
export function sanitizeRemediationSummary(value: string, maxLength = 4_000): string {
  const normalized = value
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("@", "@\u200b")
    .replace(/\r\n?/g, "\n")
    .trim();
  if (normalized.length <= maxLength) return normalized;
  const suffix = "\n\n[summary truncated]";
  return `${normalized.slice(0, Math.max(0, maxLength - suffix.length)).trimEnd()}${suffix}`;
}

function extractDeclaredPaths(chunk: string): string[] {
  const paths: string[] = [];
  for (const line of chunk.split(/\r?\n/)) {
    let raw: string | undefined;
    let stripGitPrefix = false;
    if (line.startsWith("--- ") || line.startsWith("+++ ")) {
      raw = line.slice(4).split("\t", 1)[0];
      stripGitPrefix = true;
    } else if (line.startsWith("rename from ")) {
      raw = line.slice("rename from ".length);
    } else if (line.startsWith("rename to ")) {
      raw = line.slice("rename to ".length);
    } else if (line.startsWith("copy from ")) {
      raw = line.slice("copy from ".length);
    } else if (line.startsWith("copy to ")) {
      raw = line.slice("copy to ".length);
    }
    if (!raw || raw === "/dev/null") continue;
    if (raw.startsWith('"')) {
      throw new Error("Quoted git paths are not accepted in remediation patches.");
    }
    const path = stripGitPrefix && /^(a|b)\//.test(raw) ? raw.slice(2) : raw;
    paths.push(path);
  }
  return [...new Set(paths)];
}

function validatePatchPath(path: string, allowWorkflows: boolean): void {
  if (
    !path ||
    path.startsWith("/") ||
    path.includes("\\") ||
    path.includes("\0") ||
    /[\u0000-\u001f\u007f]/.test(path)
  ) {
    throw new Error(`Unsafe remediation patch path: ${JSON.stringify(path)}.`);
  }
  const segments = path.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) {
    throw new Error(
      `Remediation patch path escapes or ambiguously addresses the repository: ${path}.`
    );
  }
  const lower = path.toLowerCase();
  if (
    lower === ".hedge.yml" ||
    lower === "threatmodel.json" ||
    lower === "threatmodel.md" ||
    lower === ".gitmodules" ||
    lower.startsWith(".git/") ||
    lower.startsWith(".hedge/")
  ) {
    throw new Error(
      `Remediation may not change Hedge policy, state, or protected metadata: ${path}.`
    );
  }
  if (!allowWorkflows && lower.startsWith(".github/workflows/")) {
    throw new Error(`Remediation may not change workflows without explicit approval: ${path}.`);
  }
  if (
    GENERATED_FILES.has(lower) ||
    GENERATED_DIRECTORIES.some((directory) => lower.startsWith(directory))
  ) {
    throw new Error(`Remediation may not change generated or dependency state: ${path}.`);
  }
}

function validateFileModes(chunk: string): void {
  for (const match of chunk.matchAll(
    /^(?:old mode|new mode|new file mode|deleted file mode) (\d{6})$/gm
  )) {
    const mode = match[1]!;
    if (!REGULAR_FILE_MODES.has(mode)) {
      throw new Error(`Remediation patch file mode ${mode} is not a regular file mode.`);
    }
  }
  if (/^(?:index [a-f0-9]+\.\.[a-f0-9]+ )?(120000|160000)$/m.test(chunk)) {
    throw new Error("Symlink and submodule patches are not allowed.");
  }
}
