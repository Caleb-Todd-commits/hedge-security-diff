import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, stat } from "node:fs/promises";
import { basename, dirname, relative, resolve, sep } from "node:path";
import { z } from "zod";
import { AttackSurfaceGraphSchema, ThreatRegisterSchema } from "../domain/schemas.js";
import { fileExists, readJsonFile, writeJsonFile } from "../utils/fs.js";
import { loadThreatRegister, validateThreatRegisterIntegrity } from "../register/store.js";
import { stableHash } from "../utils/hash.js";
import { isUnresolvedRisk } from "../register/status.js";

export interface ProofBundleOptions {
  root: string;
  output?: string;
  repository?: string;
  baseRef?: string;
  headRef?: string;
}

export interface ProofBundleFile {
  source: string;
  bundledAs: string;
  sha256: string;
  bytes: number;
}

export interface ProofBundleManifest {
  schemaVersion: "0.1";
  generatedAt: string;
  repository: string;
  baseRef?: string;
  headRef?: string;
  state: {
    graphHash?: string;
    registerHash?: string;
    sourceCommit?: string;
    configHash?: string;
    contextHash?: string;
  };
  riskSummary: {
    total: number;
    open: number;
    verified: number;
    accepted: number;
    highestOpenSeverity: string;
  };
  files: ProofBundleFile[];
  manifestDigest: string;
  notes: string[];
}

const CANDIDATES = [
  ".hedge/report.md",
  ".hedge/report.html",
  ".hedge/results.sarif",
  ".hedge/delta.json",
  ".hedge/analysis.json",
  ".hedge/graph.json",
  "THREATMODEL.md",
  "threatmodel.json"
] as const;

const SHA256 = /^[a-f0-9]{64}$/;
const ProofBundleManifestSchema = z
  .object({
    schemaVersion: z.literal("0.1"),
    generatedAt: z.string().datetime(),
    repository: z.string().min(1).max(300),
    baseRef: z.string().min(1).max(300).optional(),
    headRef: z.string().min(1).max(300).optional(),
    state: z
      .object({
        graphHash: z.string().regex(SHA256).optional(),
        registerHash: z.string().regex(SHA256).optional(),
        sourceCommit: z.string().min(1).max(300).optional(),
        configHash: z.string().regex(SHA256).optional(),
        contextHash: z.string().regex(SHA256).optional()
      })
      .strict(),
    riskSummary: z
      .object({
        total: z.number().int().nonnegative(),
        open: z.number().int().nonnegative(),
        verified: z.number().int().nonnegative(),
        accepted: z.number().int().nonnegative(),
        highestOpenSeverity: z.enum(["info", "low", "medium", "high", "critical"])
      })
      .strict(),
    files: z
      .array(
        z
          .object({
            source: z.enum(CANDIDATES),
            bundledAs: z
              .string()
              .min(1)
              .max(500)
              .refine(isSafeBundlePath, "unsafe bundled artifact path"),
            sha256: z.string().regex(SHA256),
            bytes: z
              .number()
              .int()
              .nonnegative()
              .max(8 * 1024 * 1024)
          })
          .strict()
      )
      .max(CANDIDATES.length),
    manifestDigest: z.string().regex(SHA256),
    notes: z.array(z.string().max(1000)).max(20)
  })
  .strict()
  .superRefine((manifest, context) => {
    const sources = new Set<string>();
    const destinations = new Set<string>();
    for (const file of manifest.files) {
      if (sources.has(file.source)) {
        context.addIssue({ code: "custom", message: "duplicate artifact source" });
      }
      if (destinations.has(file.bundledAs)) {
        context.addIssue({ code: "custom", message: "duplicate bundled artifact path" });
      }
      sources.add(file.source);
      destinations.add(file.bundledAs);
    }
  });

export async function createProofBundle(options: ProofBundleOptions): Promise<{
  directory: string;
  manifestPath: string;
  manifest: ProofBundleManifest;
}> {
  const root = resolve(options.root);
  const directory = resolve(root, options.output ?? ".hedge/proof");
  const filesDirectory = resolve(directory, "artifacts");
  await mkdir(filesDirectory, { recursive: true });

  const register = await loadThreatRegister(root);
  const graphPath = resolve(root, ".hedge", "graph.json");
  if (!register.graph || !(await fileExists(graphPath))) {
    throw new Error("A proof bundle requires an integrity-checked register and graph artifact.");
  }
  const standaloneGraph = AttackSurfaceGraphSchema.parse(await readJsonFile<unknown>(graphPath));
  assertGraphRegisterCoherence(standaloneGraph, register);

  const files: ProofBundleFile[] = [];
  for (const candidate of CANDIDATES) {
    const source = resolve(root, candidate);
    if (!(await fileExists(source))) continue;
    const safeName = candidate.replaceAll("/", "__").replace(/^\.+/, "");
    const destination = resolve(filesDirectory, safeName || basename(candidate));
    await mkdir(dirname(destination), { recursive: true });
    await copyFile(source, destination);
    const content = await readFile(source);
    const metadata = await stat(source);
    files.push({
      source: candidate,
      bundledAs: relative(directory, destination),
      sha256: createHash("sha256").update(content).digest("hex"),
      bytes: metadata.size
    });
  }

  const open = register.findings.filter(isUnresolvedRisk);
  const severityOrder = ["info", "low", "medium", "high", "critical"];
  const highestOpenSeverity = open.reduce(
    (highest, finding) =>
      severityOrder.indexOf(finding.severity) > severityOrder.indexOf(highest)
        ? finding.severity
        : highest,
    "info"
  );

  const configHash = await optionalFileHash(resolve(root, ".hedge.yml"));
  const contextHash = await optionalFileHash(resolve(root, ".hedge/context.yml"));
  const unsigned = {
    schemaVersion: "0.1" as const,
    generatedAt: new Date().toISOString(),
    repository: options.repository ?? register.graph?.repository ?? "local",
    baseRef: options.baseRef,
    headRef: options.headRef,
    state: {
      graphHash: register.stateIntegrity?.graphHash,
      registerHash: register.stateIntegrity?.registerHash,
      sourceCommit: register.stateIntegrity?.sourceCommit,
      configHash,
      contextHash
    },
    riskSummary: {
      total: register.findings.length,
      open: open.length,
      verified: register.findings.filter((finding) => finding.status === "verified").length,
      accepted: register.findings.filter((finding) => finding.status === "accepted").length,
      highestOpenSeverity
    },
    files,
    notes: [
      "The manifest is tamper-evident, not cryptographically signed.",
      "Configuration and reviewed context are represented by digests but are not copied into the bundle.",
      "Hedge surfaces architecture changes and design risks; it does not prove the absence of vulnerabilities."
    ]
  };
  const normalizedUnsigned = JSON.parse(JSON.stringify(unsigned)) as Omit<
    ProofBundleManifest,
    "manifestDigest"
  >;
  const manifest = ProofBundleManifestSchema.parse({
    ...normalizedUnsigned,
    manifestDigest: stableHash(normalizedUnsigned, 64)
  });
  const manifestPath = resolve(directory, "manifest.json");
  await writeJsonFile(manifestPath, manifest);
  return { directory, manifestPath, manifest };
}

export async function verifyProofBundle(manifestPath: string): Promise<string[]> {
  const absolute = resolve(manifestPath);
  const warnings: string[] = [];
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(absolute, "utf8"));
  } catch {
    return ["Proof manifest is not valid JSON."];
  }
  const parsed = ProofBundleManifestSchema.safeParse(raw);
  if (!parsed.success) return ["Proof manifest does not match the bounded v0.1 schema."];
  const manifest = parsed.data;
  const { manifestDigest, ...unsigned } = manifest;
  const computedManifestDigest = stableHash(unsigned, 64);
  if (manifestDigest !== computedManifestDigest) {
    warnings.push(
      `Manifest digest mismatch: expected ${manifestDigest}, computed ${computedManifestDigest}.`
    );
  }
  const root = dirname(absolute);
  const verifiedArtifacts = new Map<string, Buffer>();
  for (const file of manifest.files) {
    const path = resolve(root, file.bundledAs);
    if (!(await fileExists(path))) {
      warnings.push(`Missing bundled artifact ${file.bundledAs}.`);
      continue;
    }
    const content = await readFile(path);
    const digest = createHash("sha256").update(content).digest("hex");
    if (digest !== file.sha256) warnings.push(`Digest mismatch for ${file.bundledAs}.`);
    if (content.length !== file.bytes) warnings.push(`Size mismatch for ${file.bundledAs}.`);
    if (digest === file.sha256 && content.length === file.bytes) {
      verifiedArtifacts.set(file.source, content);
    }
  }
  verifyBundledStateCoherence(manifest, verifiedArtifacts, warnings);
  return warnings;
}

function assertGraphRegisterCoherence(
  graph: z.infer<typeof AttackSurfaceGraphSchema>,
  register: z.infer<typeof ThreatRegisterSchema>
): void {
  if (!register.graph || !register.stateIntegrity) {
    throw new Error("A proof bundle requires integrity-bound graph state.");
  }
  const graphHash = stableHash(graph, 64);
  const registerGraphHash = stableHash(register.graph, 64);
  if (graphHash !== registerGraphHash || graphHash !== register.stateIntegrity.graphHash) {
    throw new Error("The standalone graph, register graph, and sealed graph digest do not agree.");
  }
  if (
    graph.sourceCommit &&
    register.stateIntegrity.sourceCommit &&
    graph.sourceCommit !== register.stateIntegrity.sourceCommit
  ) {
    throw new Error("The standalone graph and register are bound to different source commits.");
  }
}

function verifyBundledStateCoherence(
  manifest: ProofBundleManifest,
  artifacts: Map<string, Buffer>,
  warnings: string[]
): void {
  const graphBytes = artifacts.get(".hedge/graph.json");
  const registerBytes = artifacts.get("threatmodel.json");
  if (!graphBytes || !registerBytes) {
    warnings.push(
      "Proof bundle is missing the graph or threat register needed for state coherence."
    );
    return;
  }
  let graphRaw: unknown;
  let registerRaw: unknown;
  try {
    graphRaw = JSON.parse(graphBytes.toString("utf8"));
    registerRaw = JSON.parse(registerBytes.toString("utf8"));
  } catch {
    warnings.push("Bundled graph or threat register is not valid JSON.");
    return;
  }
  const graphResult = AttackSurfaceGraphSchema.safeParse(graphRaw);
  const registerResult = ThreatRegisterSchema.safeParse(registerRaw);
  if (!graphResult.success || !registerResult.success) {
    warnings.push("Bundled graph or threat register does not match its strict schema.");
    return;
  }
  const registerWarnings = validateThreatRegisterIntegrity(registerResult.data, {
    raw: registerRaw
  });
  warnings.push(...registerWarnings.map((warning) => `Bundled register: ${warning}`));
  try {
    assertGraphRegisterCoherence(graphResult.data, registerResult.data);
  } catch (error) {
    warnings.push((error as Error).message);
  }
  const graphHash = stableHash(graphResult.data, 64);
  if (manifest.state.graphHash !== graphHash) {
    warnings.push("Manifest graph digest does not match the bundled graph.");
  }
  if (manifest.state.registerHash !== registerResult.data.stateIntegrity?.registerHash) {
    warnings.push("Manifest register digest does not match the bundled threat register.");
  }
  if (manifest.state.sourceCommit !== registerResult.data.stateIntegrity?.sourceCommit) {
    warnings.push("Manifest source commit does not match the bundled threat register.");
  }
  if (
    manifest.headRef &&
    /^[a-f0-9]{40,64}$/.test(manifest.headRef) &&
    graphResult.data.sourceCommit !== manifest.headRef
  ) {
    warnings.push("Manifest head revision does not match the bundled graph source commit.");
  }
}

function isSafeBundlePath(path: string): boolean {
  if (path.includes("\\") || path.includes("\0") || path.startsWith("/")) return false;
  const resolved = resolve("/bundle", path);
  return (
    resolved.startsWith(`/bundle${sep}`) &&
    !path.split("/").some((part) => !part || part === "." || part === "..")
  );
}

async function optionalFileHash(path: string): Promise<string | undefined> {
  if (!(await fileExists(path))) return undefined;
  return createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
}
