import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, stat } from "node:fs/promises";
import { basename, dirname, relative, resolve } from "node:path";
import { fileExists, writeJsonFile } from "../utils/fs.js";
import { loadThreatRegister } from "../register/store.js";
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
];

export async function createProofBundle(options: ProofBundleOptions): Promise<{
  directory: string;
  manifestPath: string;
  manifest: ProofBundleManifest;
}> {
  const root = resolve(options.root);
  const directory = resolve(root, options.output ?? ".hedge/proof");
  const filesDirectory = resolve(directory, "artifacts");
  await mkdir(filesDirectory, { recursive: true });

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

  const register = await loadThreatRegister(root);
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
  const manifest: ProofBundleManifest = {
    ...normalizedUnsigned,
    manifestDigest: stableHash(normalizedUnsigned, 64)
  };
  const manifestPath = resolve(directory, "manifest.json");
  await writeJsonFile(manifestPath, manifest);
  return { directory, manifestPath, manifest };
}

export async function verifyProofBundle(manifestPath: string): Promise<string[]> {
  const absolute = resolve(manifestPath);
  const manifest = JSON.parse(await readFile(absolute, "utf8")) as ProofBundleManifest;
  const warnings: string[] = [];
  const { manifestDigest, ...unsigned } = manifest;
  const computedManifestDigest = stableHash(unsigned, 64);
  if (manifestDigest !== computedManifestDigest) {
    warnings.push(
      `Manifest digest mismatch: expected ${manifestDigest}, computed ${computedManifestDigest}.`
    );
  }
  const root = dirname(absolute);
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
  }
  return warnings;
}

async function optionalFileHash(path: string): Promise<string | undefined> {
  if (!(await fileExists(path))) return undefined;
  return createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
}
