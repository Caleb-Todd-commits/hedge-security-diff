import * as github from "@actions/github";
import YAML from "yaml";
import {
  HedgeContextSchema,
  ThreatRegisterSchema,
  type HedgeContext,
  type ThreatRegister
} from "../domain/schemas.js";
import { parseConfigText } from "../config/load.js";
import {
  validateThreatRegisterBindings,
  validateThreatRegisterIntegrity
} from "../register/store.js";
import type { HedgeConfig } from "../domain/schemas.js";
import { relevanceScore } from "../analyzers/files.js";

export interface TrustedPullRequestState {
  config: HedgeConfig;
  register?: ThreatRegister;
  context: HedgeContext;
  patch: string;
  patchTruncated: boolean;
  patchFiles: string[];
  coverageDiagnostics: Array<{
    code: string;
    phase: "patch";
    message: string;
    file?: string;
    snapshot?: "head";
  }>;
  warnings: string[];
}

export async function loadTrustedPullRequestState(options: {
  token: string;
  baseSha: string;
  pullNumber: number;
  configPath: string;
}): Promise<TrustedPullRequestState> {
  const octokit = github.getOctokit(options.token);
  const { owner, repo } = github.context.repo;
  const warnings: string[] = [];

  const configText = await readRepositoryText({
    octokit,
    owner,
    repo,
    path: options.configPath,
    ref: options.baseSha
  });
  const config = parseConfigText(configText);
  if (configText === undefined) {
    warnings.push(
      `${options.configPath} was not present on the trusted base revision; Hedge defaults were used.`
    );
  }

  const contextText = await readRepositoryText({
    octokit,
    owner,
    repo,
    path: ".hedge/context.yml",
    ref: options.baseSha
  });
  let context: HedgeContext;
  try {
    const parsed = contextText ? YAML.parse(contextText) : {};
    context = HedgeContextSchema.parse(parsed);
  } catch (error) {
    warnings.push(
      `The trusted base .hedge/context.yml could not be parsed; empty reviewed context was used: ${(error as Error).message}`
    );
    context = HedgeContextSchema.parse({});
  }

  const registerText = await readRepositoryText({
    octokit,
    owner,
    repo,
    path: "threatmodel.json",
    ref: options.baseSha
  });
  let register: ThreatRegister | undefined;
  if (registerText !== undefined) {
    const parsedRegister = parseTrustedThreatRegisterText(registerText, {
      config,
      context,
      baseSha: options.baseSha
    });
    register = parsedRegister.register;
    warnings.push(...parsedRegister.warnings);
  } else {
    warnings.push(
      "No threatmodel.json existed on the trusted base revision; lifecycle state is unavailable and the exact base graph will be rebuilt from source."
    );
  }

  const files = await octokit.paginate(octokit.rest.pulls.listFiles, {
    owner,
    repo,
    pull_number: options.pullNumber,
    per_page: 100
  });
  const selected = prioritizePullRequestFiles(files).slice(0, config.limits.max_files);
  if (files.length > selected.length) {
    warnings.push(
      `The PR contains ${files.length} files; only the first ${selected.length} were included in the patch evidence budget.`
    );
  }

  const pieces: string[] = [];
  const coverageDiagnostics: TrustedPullRequestState["coverageDiagnostics"] = [];
  let bytes = 0;
  let patchTruncated = files.length > selected.length;
  if (files.length > selected.length) {
    coverageDiagnostics.push({
      code: "patch-file-limit-exceeded",
      phase: "patch",
      snapshot: "head",
      message: `${files.length - selected.length} changed file patch(es) exceeded the trusted file budget.`
    });
  }
  for (const file of selected) {
    const header = `diff --git a/${file.filename} b/${file.filename}\n--- a/${file.previous_filename ?? file.filename}\n+++ b/${file.filename}\n`;
    const body = file.patch ?? `[patch unavailable for ${file.status} file]\n`;
    if (file.patch === undefined) {
      patchTruncated = true;
      coverageDiagnostics.push({
        code: "patch-unavailable",
        phase: "patch",
        snapshot: "head",
        file: file.filename,
        message: `GitHub did not provide a bounded patch for this ${file.status ?? "changed"} file.`
      });
    }
    const piece = `${header}${body}\n`;
    const size = Buffer.byteLength(piece, "utf8");
    if (bytes + size > config.limits.max_bytes) {
      const remaining = Math.max(0, config.limits.max_bytes - bytes);
      if (remaining > 0) pieces.push(truncateUtf8(piece, remaining));
      patchTruncated = true;
      coverageDiagnostics.push({
        code: "patch-byte-limit-exceeded",
        phase: "patch",
        snapshot: "head",
        file: file.filename,
        message: "PR patch evidence exceeded the trusted byte budget."
      });
      break;
    }
    pieces.push(piece);
    bytes += size;
  }

  return {
    config,
    register,
    context,
    patch: pieces.join(""),
    patchTruncated,
    patchFiles: selected.map((file) => file.filename),
    coverageDiagnostics,
    warnings
  };
}

export function parseTrustedThreatRegisterText(
  text: string,
  bindings: { config: HedgeConfig; context: HedgeContext; baseSha: string }
): { register?: ThreatRegister; warnings: string[] } {
  const warnings: string[] = [];
  try {
    const raw = JSON.parse(text) as unknown;
    const register = ThreatRegisterSchema.parse(raw);
    const integrityWarnings = validateThreatRegisterIntegrity(register, { raw });
    if (integrityWarnings.length) {
      warnings.push(
        `The trusted base threatmodel.json failed its full-register integrity digest and the entire register was ignored: ${integrityWarnings.join(" ")}`
      );
      return { warnings };
    }

    const bindingWarnings = validateThreatRegisterBindings(register, {
      config: bindings.config,
      context: bindings.context,
      sourceCommit: bindings.baseSha
    });
    if (bindingWarnings.length) {
      warnings.push(
        `The trusted baseline may be stale and should be refreshed after this review: ${bindingWarnings.join(" ")}`
      );
    }
    return { register, warnings };
  } catch (error) {
    warnings.push(
      `The trusted base threatmodel.json could not be parsed and was ignored: ${(error as Error).message}`
    );
    return { warnings };
  }
}

export interface PullRequestFileLike {
  filename: string;
  previous_filename?: string;
  status?: string;
  patch?: string;
}

export function prioritizePullRequestFiles<T extends PullRequestFileLike>(files: T[]): T[] {
  return [...files].sort((a, b) => {
    const scoreA = Math.max(relevanceScore(a.filename), relevanceScore(a.previous_filename ?? ""));
    const scoreB = Math.max(relevanceScore(b.filename), relevanceScore(b.previous_filename ?? ""));
    return scoreB - scoreA || a.filename.localeCompare(b.filename);
  });
}

function truncateUtf8(value: string, maxBytes: number): string {
  if (maxBytes <= 0) return "";
  const buffer = Buffer.from(value, "utf8");
  if (buffer.length <= maxBytes) return value;
  let end = maxBytes;
  while (end > 0 && (buffer[end]! & 0xc0) === 0x80) end -= 1;
  return `${buffer.subarray(0, end).toString("utf8")}
[HEDGE PATCH EVIDENCE TRUNCATED]
`;
}

type Octokit = ReturnType<typeof github.getOctokit>;

async function readRepositoryText(options: {
  octokit: Octokit;
  owner: string;
  repo: string;
  path: string;
  ref: string;
}): Promise<string | undefined> {
  try {
    const response = await options.octokit.rest.repos.getContent({
      owner: options.owner,
      repo: options.repo,
      path: options.path,
      ref: options.ref
    });
    if (
      Array.isArray(response.data) ||
      response.data.type !== "file" ||
      !("content" in response.data)
    ) {
      return undefined;
    }
    return Buffer.from(response.data.content, response.data.encoding as BufferEncoding).toString(
      "utf8"
    );
  } catch (error) {
    const status = (error as { status?: number }).status;
    if (status === 404) return undefined;
    throw error;
  }
}
