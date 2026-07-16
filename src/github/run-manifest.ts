import { createHash, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import {
  AnalysisHealthSchema,
  CoverageDiagnosticSchema,
  CoverageSchema,
  RunManifestSchema,
  type RunManifest
} from "../domain/schemas.js";
import { stableHash, stableStringify } from "../utils/hash.js";

export type RunArtifactBytes = string | Uint8Array;

export interface RunManifestLimits {
  maxManifestBytes?: number;
  maxArtifacts?: number;
  maxArtifactBytes?: number;
  maxTotalArtifactBytes?: number;
}

export interface RunManifestBindings {
  repository: string;
  pullRequest?: number;
  baseSha: string;
  headSha: string;
  workflowRef: string;
  actionVersion?: string;
}

export interface CreateRunManifestOptions extends Omit<
  RunManifest,
  "schemaVersion" | "createdAt" | "artifacts" | "manifestDigest"
> {
  createdAt?: string;
  artifacts: Readonly<Record<string, RunArtifactBytes>>;
  limits?: RunManifestLimits;
}

export interface VerifyRunBundleOptions {
  /** Prefer the exact downloaded manifest bytes at a publication boundary. */
  manifest: unknown;
  artifacts: Readonly<Record<string, RunArtifactBytes>>;
  expected: RunManifestBindings;
  limits?: RunManifestLimits;
}

export interface VerifiedRunBundle {
  manifest: RunManifest;
  artifacts: Readonly<Record<string, Uint8Array>>;
  totalArtifactBytes: number;
}

export const DEFAULT_RUN_MANIFEST_LIMITS = Object.freeze({
  maxManifestBytes: 128 * 1024,
  maxArtifacts: 32,
  maxArtifactBytes: 2 * 1024 * 1024,
  maxTotalArtifactBytes: 8 * 1024 * 1024
});

const DIGEST_PATTERN = /^[a-f0-9]{64}$/;
const REVISION_PATTERN = /^[a-f0-9]{40,64}$/;
const ARTIFACT_SEGMENT_PATTERN = /^[A-Za-z0-9._@+-]+$/;

const StrictCoverageDiagnosticSchema = CoverageDiagnosticSchema.strict();
const StrictCoverageSchema = CoverageSchema.extend({
  omitted: CoverageSchema.shape.omitted.strict(),
  diagnostics: z.array(StrictCoverageDiagnosticSchema).default([])
}).strict();
const StrictAnalysisHealthSchema = AnalysisHealthSchema.strict();
const StrictRunManifestSchema = RunManifestSchema.extend({
  coverage: StrictCoverageSchema,
  analysisHealth: StrictAnalysisHealthSchema
}).strict();
const StrictUnsignedRunManifestSchema = StrictRunManifestSchema.omit({ manifestDigest: true });

type UnsignedRunManifest = z.infer<typeof StrictUnsignedRunManifestSchema>;
type ResolvedLimits = Required<RunManifestLimits>;

/** Create a canonical v0.1 manifest whose digests cover the exact artifact bytes. */
export function createRunManifest(options: CreateRunManifestOptions): RunManifest {
  const limits = resolveLimits(options.limits);
  const normalizedArtifacts = normalizeArtifacts(options.artifacts, limits);
  const artifactDigests = Object.fromEntries(
    Object.entries(normalizedArtifacts.artifacts)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([name, bytes]) => [name, sha256(bytes)])
  );

  const { createdAt, artifacts: _artifacts, limits: _limits, ...metadata } = options;
  const unsigned = StrictUnsignedRunManifestSchema.parse({
    schemaVersion: "0.1",
    createdAt: createdAt ?? new Date().toISOString(),
    ...metadata,
    artifacts: artifactDigests
  });
  validateManifestSemantics(unsigned, limits);

  const manifest = StrictRunManifestSchema.parse({
    ...unsigned,
    manifestDigest: computeRunManifestDigest(unsigned)
  });
  assertManifestWithinLimit(manifest, limits);
  return manifest;
}

/** Compute the canonical digest over every manifest field except manifestDigest. */
export function computeRunManifestDigest(
  manifest: RunManifest | Omit<RunManifest, "manifestDigest">
): string {
  const candidate = { ...manifest } as Partial<RunManifest>;
  delete candidate.manifestDigest;
  const unsigned = StrictUnsignedRunManifestSchema.parse(candidate);
  return stableHash(unsigned, 64);
}

/** Serialize a validated manifest for an artifact handoff. */
export function serializeRunManifest(
  manifest: RunManifest,
  limits?: RunManifestLimits
): Uint8Array {
  const resolved = resolveLimits(limits);
  const parsed = StrictRunManifestSchema.parse(manifest);
  validateManifestSemantics(parsed, resolved);
  verifyDigest(parsed.manifestDigest, computeRunManifestDigest(parsed), "Run manifest");
  const bytes = Buffer.from(`${JSON.stringify(parsed, null, 2)}\n`, "utf8");
  if (bytes.byteLength > resolved.maxManifestBytes) {
    throw new Error(
      `Run manifest is ${bytes.byteLength} bytes; limit is ${resolved.maxManifestBytes}.`
    );
  }
  return bytes;
}

/**
 * Validate an untrusted reasoning bundle before any GitHub-authorized publisher
 * consumes it. The expected head SHA must be re-fetched immediately beforehand.
 */
export function verifyRunBundle(options: VerifyRunBundleOptions): VerifiedRunBundle {
  const limits = resolveLimits(options.limits);
  const manifest = parseUntrustedManifest(options.manifest, limits);
  validateManifestSemantics(manifest, limits);
  verifyDigest(manifest.manifestDigest, computeRunManifestDigest(manifest), "Run manifest");
  verifyBindings(manifest, options.expected);

  const normalizedArtifacts = normalizeArtifacts(options.artifacts, limits);
  const expectedNames = Object.keys(manifest.artifacts).sort();
  const actualNames = Object.keys(normalizedArtifacts.artifacts).sort();
  if (!sameStrings(expectedNames, actualNames)) {
    const missing = expectedNames.filter((name) => !actualNames.includes(name));
    const unexpected = actualNames.filter((name) => !expectedNames.includes(name));
    throw new Error(
      `Run artifact inventory mismatch (missing: ${missing.join(", ") || "none"}; unexpected: ${unexpected.join(", ") || "none"}).`
    );
  }

  for (const name of expectedNames) {
    const bytes = normalizedArtifacts.artifacts[name];
    if (!bytes) throw new Error(`Run artifact ${name} is missing.`);
    verifyDigest(manifest.artifacts[name]!, sha256(bytes), `Run artifact ${name}`);
  }

  return {
    manifest,
    artifacts: Object.freeze(normalizedArtifacts.artifacts),
    totalArtifactBytes: normalizedArtifacts.totalBytes
  };
}

function parseUntrustedManifest(value: unknown, limits: ResolvedLimits): RunManifest {
  let candidate: unknown = value;
  if (typeof value === "string" || value instanceof Uint8Array) {
    const bytes = typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value);
    if (bytes.byteLength > limits.maxManifestBytes) {
      throw new Error(
        `Run manifest is ${bytes.byteLength} bytes; limit is ${limits.maxManifestBytes}.`
      );
    }
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new Error("Run manifest is not valid UTF-8.");
    }
    try {
      candidate = JSON.parse(text) as unknown;
    } catch {
      throw new Error("Run manifest is not valid JSON.");
    }
  } else {
    assertManifestWithinLimit(value, limits);
  }

  const result = StrictRunManifestSchema.safeParse(candidate);
  if (!result.success) {
    throw new Error(`Run manifest schema validation failed: ${z.prettifyError(result.error)}`);
  }
  if (stableStringify(candidate) !== stableStringify(result.data)) {
    throw new Error("Run manifest contains unknown, missing-default, or non-canonical fields.");
  }
  return result.data;
}

function validateManifestSemantics(
  manifest: RunManifest | UnsignedRunManifest,
  limits: ResolvedLimits
): void {
  if (!isCanonicalTimestamp(manifest.createdAt)) {
    throw new Error("Run manifest createdAt must be a canonical ISO-8601 timestamp.");
  }
  validateBoundedText(manifest.repository, "repository", 256);
  validateRevision(manifest.baseSha, "base SHA");
  validateRevision(manifest.headSha, "head SHA");
  validateBoundedText(manifest.workflowRef, "workflow ref", 512);
  validateBoundedText(manifest.actionVersion, "action version", 128);
  validateBoundedText(manifest.extractorVersion, "extractor version", 128);
  validateBoundedText(manifest.artifactSchemaVersion, "artifact schema version", 128);
  if (manifest.promptVersion !== undefined) {
    validateBoundedText(manifest.promptVersion, "prompt version", 128);
  }
  if (manifest.model !== undefined) validateBoundedText(manifest.model, "model", 128);

  const names = Object.keys(manifest.artifacts);
  if (names.length < 1) throw new Error("Run manifest must bind at least one artifact.");
  if (names.length > limits.maxArtifacts) {
    throw new Error(
      `Run manifest binds ${names.length} artifacts; limit is ${limits.maxArtifacts}.`
    );
  }
  for (const name of names) {
    validateArtifactName(name);
    const digest = manifest.artifacts[name];
    if (!digest || !DIGEST_PATTERN.test(digest)) {
      throw new Error(`Run artifact ${name} does not have a valid SHA-256 digest.`);
    }
  }
}

function verifyBindings(manifest: RunManifest, expected: RunManifestBindings): void {
  validateBoundedText(expected.repository, "expected repository", 256);
  validateRevision(expected.baseSha, "expected base SHA");
  validateRevision(expected.headSha, "expected head SHA");
  validateBoundedText(expected.workflowRef, "expected workflow ref", 512);
  if (expected.actionVersion !== undefined) {
    validateBoundedText(expected.actionVersion, "expected action version", 128);
  }

  if (manifest.repository !== expected.repository) {
    throw new Error("Run manifest repository binding does not match the publication target.");
  }
  if (manifest.pullRequest !== expected.pullRequest) {
    throw new Error("Run manifest pull-request binding does not match the publication target.");
  }
  if (manifest.baseSha !== expected.baseSha) {
    throw new Error("Run manifest base-SHA binding does not match the current pull request.");
  }
  if (manifest.headSha !== expected.headSha) {
    throw new Error("Run manifest is stale for the current pull-request head.");
  }
  if (manifest.workflowRef !== expected.workflowRef) {
    throw new Error("Run manifest workflow binding does not match the authorized workflow.");
  }
  if (expected.actionVersion !== undefined && manifest.actionVersion !== expected.actionVersion) {
    throw new Error("Run manifest action-version binding does not match the publisher.");
  }
}

function normalizeArtifacts(
  artifacts: Readonly<Record<string, RunArtifactBytes>>,
  limits: ResolvedLimits
): { artifacts: Record<string, Uint8Array>; totalBytes: number } {
  if (!artifacts || typeof artifacts !== "object" || Array.isArray(artifacts)) {
    throw new Error("Run artifacts must be a named byte map.");
  }
  const entries = Object.entries(artifacts);
  if (entries.length < 1) throw new Error("At least one run artifact is required.");
  if (entries.length > limits.maxArtifacts) {
    throw new Error(
      `Run bundle contains ${entries.length} artifacts; limit is ${limits.maxArtifacts}.`
    );
  }

  const normalized: Record<string, Uint8Array> = Object.create(null) as Record<string, Uint8Array>;
  let totalBytes = 0;
  for (const [name, value] of entries) {
    validateArtifactName(name);
    if (typeof value !== "string" && !(value instanceof Uint8Array)) {
      throw new Error(`Run artifact ${name} must contain bytes or UTF-8 text.`);
    }
    const bytes = typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value);
    if (bytes.byteLength > limits.maxArtifactBytes) {
      throw new Error(
        `Run artifact ${name} is ${bytes.byteLength} bytes; per-artifact limit is ${limits.maxArtifactBytes}.`
      );
    }
    totalBytes += bytes.byteLength;
    if (totalBytes > limits.maxTotalArtifactBytes) {
      throw new Error(
        `Run artifacts total ${totalBytes} bytes; limit is ${limits.maxTotalArtifactBytes}.`
      );
    }
    normalized[name] = Uint8Array.from(bytes);
  }
  return { artifacts: normalized, totalBytes };
}

function validateArtifactName(name: string): void {
  if (
    !name ||
    name.length > 240 ||
    Buffer.byteLength(name, "utf8") > 240 ||
    name.startsWith("/") ||
    name.includes("\\") ||
    name.includes("\0") ||
    /[\u0000-\u001f\u007f]/.test(name)
  ) {
    throw new Error(`Unsafe run artifact path: ${JSON.stringify(name)}.`);
  }
  const segments = name.split("/");
  if (
    segments.some(
      (segment) =>
        !segment || segment === "." || segment === ".." || !ARTIFACT_SEGMENT_PATTERN.test(segment)
    )
  ) {
    throw new Error(`Run artifact path is unsafe or non-canonical: ${name}.`);
  }
}

function validateRevision(value: string, label: string): void {
  if (!REVISION_PATTERN.test(value)) {
    throw new Error(`Run manifest ${label} must be an exact lowercase commit SHA.`);
  }
}

function validateBoundedText(value: string, label: string, maxLength: number): void {
  if (!value || value.length > maxLength || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(`Run manifest ${label} is empty, oversized, or contains control characters.`);
  }
}

function isCanonicalTimestamp(value: string): boolean {
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
}

function assertManifestWithinLimit(value: unknown, limits: ResolvedLimits): void {
  let serialized: string;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new Error("Run manifest is not JSON-serializable.");
  }
  if (serialized === undefined) throw new Error("Run manifest must be a JSON object.");
  const bytes = Buffer.byteLength(serialized, "utf8");
  if (bytes > limits.maxManifestBytes) {
    throw new Error(`Run manifest is ${bytes} bytes; limit is ${limits.maxManifestBytes}.`);
  }
}

function resolveLimits(limits: RunManifestLimits | undefined): ResolvedLimits {
  const resolved = { ...DEFAULT_RUN_MANIFEST_LIMITS, ...limits };
  for (const [name, value] of Object.entries(resolved)) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new Error(`Run manifest limit ${name} must be a positive safe integer.`);
    }
  }
  return resolved;
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function verifyDigest(expected: string, actual: string, label: string): void {
  if (!DIGEST_PATTERN.test(expected) || !DIGEST_PATTERN.test(actual)) {
    throw new Error(`${label} digest is malformed.`);
  }
  if (!timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(actual, "hex"))) {
    throw new Error(`${label} digest mismatch.`);
  }
}

function sameStrings(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
